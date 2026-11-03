--[[--
Hardcover (hardcover.app) integration.

- Browse your Hardcover lists and series trackers, see each book's full
  details, search and sort books, and attach a local file to read it in KOReader.
- Find books from all lists and series that still need a local attachment.
- Suggest local matches, scan and repair stale file references, and preview
  collection refreshes before applying them.
- Mirror lists and series trackers into KOReader collections, compare local
  and Hardcover reading progress, and back up attachment mappings.

@module koplugin.hardcover
]]--

local DataStorage = require("datastorage")
local Device = require("device")
local ButtonDialog = require("ui/widget/buttondialog")
local ConfirmBox = require("ui/widget/confirmbox")
local DocumentRegistry = require("document/documentregistry")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local DocSettings = require("docsettings")
local JSON = require("json")
local LuaSettings = require("luasettings")
local Menu = require("ui/widget/menu")
local NetworkMgr = require("ui/network/manager")
local PathChooser = require("ui/widget/pathchooser")
local ReadCollection = require("readcollection")
local UIManager = require("ui/uimanager")
local Trapper = require("ui/trapper")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local filemanagerutil = require("apps/filemanager/filemanagerutil")
local lfs = require("libs/libkoreader-lfs")
local logger = require("logger")
local ltn12 = require("ltn12")
local http = require("socket.http")
local mime = require("mime")
local ssl = require("ssl")
local https = require("ssl.https")
local socket = require("socket")
local url = require("socket.url")
local socketutil = require("socketutil")
local _ = require("gettext")
local ffiUtil = require("ffi/util")
local util = require("util")
local T = ffiUtil.template

local API_URL = "https://api.hardcover.app/v1/graphql"

local COLLECTION_PREFIX = "HC: " -- KOReader collection name prefix for Hardcover lists

local Hardcover = WidgetContainer:extend{
    name = "hardcover",
    is_doc_only = false,
    settings = nil,
}

local function getProxyURL()
    if G_reader_settings:readSetting("http_proxy_enabled") then
        local configured_proxy = G_reader_settings:readSetting("http_proxy")
        if configured_proxy and configured_proxy ~= "" then
            return configured_proxy
        end
    end

    local function firstNonEmpty(...)
        for i = 1, select("#", ...) do
            local value = select(i, ...)
            if value and value ~= "" then
                return value
            end
        end
    end

    return firstNonEmpty(
        http.PROXY,
        os.getenv("HTTPS_PROXY"),
        os.getenv("https_proxy"),
        os.getenv("HTTP_PROXY"),
        os.getenv("http_proxy")
    )
end

local function parseProxyURL(proxy_url)
    local proxy = url.parse(proxy_url)
    if not proxy or not proxy.host or string.lower(proxy.scheme or "") ~= "http" then
        return nil, "Only HTTP CONNECT proxies are supported."
    end

    proxy.port = tonumber(proxy.port) or 3128
    if proxy.port < 1 or proxy.port > 65535 then
        return nil, "Invalid proxy port."
    end

    local username = proxy.user and url.unescape(proxy.user)
    if username then
        local password = url.unescape(proxy.password or "")
        proxy.authorization = "Proxy-Authorization: Basic "
            .. mime.b64(username .. ":" .. password):gsub("[\r\n]", "") .. "\r\n"
    else
        proxy.authorization = ""
    end

    return proxy
end

local function createProxyConnection(proxy)
    return function()
        local connection = {
            timeout = http.TIMEOUT,
        }

        function connection:settimeout(timeout)
            self.timeout = timeout
            if self.sock then
                return self.sock:settimeout(timeout)
            end
            return 1
        end

        function connection:connect(host, port)
            local raw_socket = socket.tcp()
            raw_socket:settimeout(self.timeout)
            local connected, err = raw_socket:connect(proxy.host, proxy.port)
            if not connected then
                raw_socket:close()
                return nil, err
            end

            local authority = host .. ":" .. port
            local request = "CONNECT " .. authority .. " HTTP/1.1\r\n"
                .. "Host: " .. authority .. "\r\n"
                .. proxy.authorization
                .. "Proxy-Connection: keep-alive\r\n\r\n"
            local sent, send_err = raw_socket:send(request)
            if not sent then
                raw_socket:close()
                return nil, send_err
            end

            local status_line, receive_err = raw_socket:receive("*l")
            local status_code = status_line
                and tonumber(status_line:match("^HTTP/%d+%.%d+%s+(%d%d%d)"))
            if not status_code then
                raw_socket:close()
                return nil, receive_err or "Invalid proxy response."
            end

            while true do
                local header_line, header_err = raw_socket:receive("*l")
                if not header_line then
                    raw_socket:close()
                    return nil, header_err
                end
                if header_line == "" or header_line == "\r" then
                    break
                end
            end

            if status_code ~= 200 then
                raw_socket:close()
                return nil, ("Proxy CONNECT failed (HTTP %d)."):format(status_code)
            end

            local ca_file = ssl.get_system_ca()
            local tls_params = {
                protocol = "any",
                options = { "all", "no_sslv2", "no_sslv3", "no_tlsv1" },
                mode = "client",
                cafile = ca_file,
                verify = ca_file and "peer" or "none",
            }
            local tls_socket, tls_err = ssl.wrap(raw_socket, tls_params)
            if not tls_socket then
                raw_socket:close()
                return nil, tls_err
            end

            tls_socket:sni(host)
            tls_socket:settimeout(self.timeout)
            local handshook, handshake_err = tls_socket:dohandshake()
            if not handshook then
                tls_socket:close()
                return nil, handshake_err
            end
            if not tls_socket:checkhostname(host) then
                tls_socket:close()
                return nil, "Hostname does not match certificate."
            end

            self.sock = tls_socket
            return 1
        end

        function connection:send(...)
            return self.sock:send(...)
        end

        function connection:receive(...)
            return self.sock:receive(...)
        end

        function connection:getfd()
            return self.sock:getfd()
        end

        function connection:dirty()
            return self.sock:dirty()
        end

        function connection:close()
            if self.sock then
                return self.sock:close()
            end
            return 1
        end

        return connection
    end
end

-- LuaSec rejects socket.http.PROXY, so HTTPS proxies need an explicit CONNECT tunnel.
local function proxyRequest(proxy_url, request)
    local proxy, err = parseProxyURL(proxy_url)
    if not proxy then
        return nil, nil, nil, err
    end

    request.create = createProxyConnection(proxy)

    local configured_proxy = http.PROXY
    http.PROXY = nil
    local ok, result, code, headers, status = pcall(http.request, request)
    http.PROXY = configured_proxy
    if not ok then
        return nil, nil, nil, result
    end
    return result, code, headers, status
end

function Hardcover:init()
    self.settings = LuaSettings:open(DataStorage:getSettingsDir() .. "/hardcover.lua")
    self.ui.menu:registerToMainMenu(self)
end

-- ----------------------------------------------------------------: GraphQL --

--- Execute a GraphQL query against the Hardcover API.
--- Returns the `me` object on success, nil otherwise (error already shown).
function Hardcover:query(query_text)
    if not self:getToken() then
        self.last_query_error = _("No access token is configured.")
        self:promptForToken()
        return nil
    end

    local sink = {}
    local body = JSON.encode({ query = query_text })
    local request = {
        url = API_URL,
        method = "POST",
        headers = {
            ["Authorization"] = "Bearer " .. self:getToken(),
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #body,
        },
        source = ltn12.source.string(body),
        sink = ltn12.sink.table(sink),
    }

    socketutil:set_timeout(socketutil.LARGE_TIMEOUT)
    local code, resp_headers, status
    local proxy_url = getProxyURL()
    if proxy_url then
        local _, proxy_code, proxy_headers, proxy_status = proxyRequest(proxy_url, request)
        code, resp_headers, status = proxy_code, proxy_headers, proxy_status
    else
        code, resp_headers, status = socket.skip(1, https.request(request))
    end
    socketutil:reset_timeout()

    if resp_headers == nil then
        local message = status or code or _("unknown network error")
        self.last_query_error = tostring(message)
        logger.err("Hardcover:query network error", message)
        self:recordDiagnostic("API", self.last_query_error)
        UIManager:show(InfoMessage:new{ text = _("Network error.") })
        return nil
    end
    if code ~= 200 then
        logger.err("Hardcover:query HTTP", code)
        local message
        if code == 401 then
            message = _("Hardcover rejected the access token. Please set a valid token and try again.")
        else
            message = T(_("Request failed (HTTP %1)."), code)
        end
        self.last_query_error = message
        self:recordDiagnostic("API", message)
        UIManager:show(InfoMessage:new{ text = message })
        return nil
    end

    local ok, result = pcall(JSON.decode, table.concat(sink))
    if not ok or type(result) ~= "table" then
        logger.err("Hardcover:query invalid JSON")
        self.last_query_error = _("Server response is not valid.")
        self:recordDiagnostic("API", self.last_query_error)
        UIManager:show(InfoMessage:new{ text = _("Server response is not valid.") })
        return nil
    end
    if result.errors then
        local msg = result.errors[1] and result.errors[1].message or "unknown"
        logger.err("Hardcover:query GraphQL errors", msg)
        self.last_query_error = tostring(msg)
        self:recordDiagnostic("API", self.last_query_error)
        UIManager:show(InfoMessage:new{ text = T(_("API error: %1"), msg) })
        return nil
    end
    self.last_query_error = nil
    return result.data
end

-- --------------------------------------------------------------: settings --

function Hardcover:getToken()
    return self.settings:readSetting("access_token")
end

--- Local file attached to a Hardcover book id (path or nil).
function Hardcover:getAttachment(book_id)
    local files = self.settings:readSetting("attachments") or {}
    return files[tostring(book_id)]
end

function Hardcover:setAttachment(book_id, file_path)
    local files = self.settings:readSetting("attachments") or {}
    if file_path then
        files[tostring(book_id)] = file_path
    else
        files[tostring(book_id)] = nil
    end
    self.settings:saveSetting("attachments", files)
    self.settings:flush()
end

function Hardcover:recordSyncStatus(kind, summary, failed)
    local sync_status = self.settings:readSetting("sync_status") or {}
    sync_status[kind] = {
        timestamp = os.time(),
        summary = summary,
        failed = failed or false,
    }
    self.settings:saveSetting("sync_status", sync_status)
    self.settings:flush()
end

function Hardcover:recordDiagnostic(operation, message, retry)
    if not self.settings then return end
    local diagnostics = self.settings:readSetting("sync_diagnostics") or {}
    table.insert(diagnostics, {
        timestamp = os.time(),
        operation = operation,
        message = tostring(message),
        retry = retry,
    })
    while #diagnostics > 20 do table.remove(diagnostics, 1) end
    self.settings:saveSetting("sync_diagnostics", diagnostics)
    self.settings:flush()
end

local function displayTimestamp(timestamp)
    local epoch = tonumber(timestamp)
    if epoch then return os.date("%Y-%m-%d %H:%M", epoch) end
    return type(timestamp) == "string" and timestamp or _("Never")
end

local function getCachedBookCounts(self)
    local books, unattached = {}, 0
    local lists = self:loadJson("lists.json") or {}
    local series = self:loadJson("series.json") or {}
    for _, list in ipairs(lists) do
        for _, book in ipairs(self:loadJson(("list_%d_books.json"):format(list.id)) or {}) do
            books[tostring(book.id)] = book
        end
    end
    for _, tracker in ipairs(series) do
        local series_id = tracker.id or (tracker.series and tracker.series.id)
        if series_id then
            for _, book in ipairs(self:loadJson(("series_%d_books.json"):format(series_id)) or {}) do
                books[tostring(book.id)] = book
            end
        end
    end
    for _, book in pairs(books) do
        if not self:getAttachment(book.id) then unattached = unattached + 1 end
    end
    return #lists, #series, unattached
end

function Hardcover:showSyncStatus()
    local sync_status = self.settings:readSetting("sync_status") or {}
    local lines = {}
    local status_has_errors = false
    local kinds = {
        { key = "lists", label = _("List collections") },
        { key = "series", label = _("Series collections") },
        { key = "progress", label = _("Reading progress") },
        { key = "collection_refresh", label = _("Collection refresh") },
        { key = "backup_restore", label = _("Backup restore") },
    }
    for _, kind in ipairs(kinds) do
        local entry = sync_status[kind.key]
        if entry then
            table.insert(lines, T(_("%1: %2\n%3"),
                kind.label, displayTimestamp(entry.timestamp), entry.summary))
            if entry.failed then status_has_errors = true end
        else
            table.insert(lines, T(_("%1: Never synced"), kind.label))
        end
    end
    local cache_timestamps = self.settings:readSetting("cache_timestamps") or {}
    local function cacheLineForTimestamp(timestamp, label)
        if not timestamp then return T(_("%1 cache: Never refreshed"), label) end
        local age_days = math.floor(math.max(0, os.time() - timestamp) / 86400)
        local freshness = age_days > 7 and T(_("STALE — %1 days old"), age_days)
            or age_days == 0 and _("fresh today") or T(_("%1 days old"), age_days)
        return T(_("%1 cache: %2 (%3)"), label, displayTimestamp(timestamp), freshness)
    end
    local function cacheLine(key, label)
        return cacheLineForTimestamp(cache_timestamps[key], label)
    end
    local oldest_book_cache
    for key, timestamp in pairs(cache_timestamps) do
        if key:match("^list_%d+_books%.json$") or key:match("^series_%d+_books%.json$") then
            oldest_book_cache = oldest_book_cache and math.min(oldest_book_cache, timestamp) or timestamp
        end
    end
    local list_count, series_count, unattached_count = getCachedBookCounts(self)
    table.insert(lines, cacheLine("lists.json", _("Lists")))
    table.insert(lines, cacheLine("series.json", _("Series")))
    table.insert(lines, cacheLineForTimestamp(oldest_book_cache, _("Book details")))
    table.insert(lines, T(_("Cached: %1 lists, %2 series, %3 books still to attach."),
        list_count, series_count, unattached_count))
    local pending_additions, pending_removals = self:getCachedPendingCollectionChanges()
    table.insert(lines, T(_("Pending cached collection changes: %1 additions, %2 outdated mirrored entries."),
        pending_additions, pending_removals))

    local stale_count = 0
    for _, path in pairs(self.settings:readSetting("attachments") or {}) do
        if type(path) ~= "string" or lfs.attributes(path, "mode") ~= "file" then
            stale_count = stale_count + 1
        end
    end
    table.insert(lines, T(_("Missing local attachments: %1"), stale_count))
    local diagnostics = self.settings:readSetting("sync_diagnostics") or {}
    if #diagnostics > 0 then status_has_errors = true end

    local items = {
        { text = _("Sync list collections"), action = "lists" },
        { text = _("Sync series collections"), action = "series" },
        { text = _("View recent sync errors"), action = "errors",
            mandatory = status_has_errors and _("Needs attention") or nil },
        { text = _("Export plugin backup"), action = "export" },
        { text = _("Restore plugin backup"), action = "import" },
    }
    local menu = Menu:new{
        title = _("Hardcover sync dashboard\n\n") .. table.concat(lines, "\n\n"),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            if item.action == "lists" then
                self:syncListsToCollections()
            elseif item.action == "series" then
                self:syncSeriesToCollections()
            elseif item.action == "errors" then
                self:showSyncDiagnostics()
            elseif item.action == "export" then
                self:chooseBackupExportFolder()
            elseif item.action == "import" then
                self:chooseBackupImportFile()
            end
        end,
    }
    UIManager:show(menu)
end

function Hardcover:showSyncDiagnostics()
    local diagnostics = self.settings:readSetting("sync_diagnostics") or {}
    local items = {
        { text = _("Retry list collection sync"), action = "lists" },
        { text = _("Retry series collection sync"), action = "series" },
        { text = _("Retry reading progress review"), action = "progress" },
        { text = _("Clear sync error history"), action = "clear" },
    }
    for index = #diagnostics, 1, -1 do
        local entry = diagnostics[index]
        table.insert(items, {
            text = T(_("%1: %2"), displayTimestamp(entry.timestamp), entry.operation),
            detail = entry.message,
        })
        if entry.retry then
            table.insert(items, {
                text = T(_("Retry: %1"), entry.operation),
                retry = entry.retry,
            })
        end
    end
    if #diagnostics == 0 then
        table.insert(items, { text = _("No recent sync errors."), dim = true })
    end
    local menu = Menu:new{
        title = _("Recent sync errors"),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            if item.action == "lists" then
                self:syncListsToCollections()
            elseif item.action == "series" then
                self:syncSeriesToCollections()
            elseif item.action == "progress" then
                self:syncReadingProgress()
            elseif item.action == "clear" then
                UIManager:show(ConfirmBox:new{
                    text = _("Clear the saved sync error history?"),
                    ok_text = _("Clear"),
                    ok_callback = function()
                        self.settings:saveSetting("sync_diagnostics", {})
                        self.settings:flush()
                        UIManager:show(InfoMessage:new{ text = _("Sync error history cleared."), timeout = 4 })
                    end,
                })
            elseif item.retry then
                self:retryCollectionRefresh(item.retry)
            elseif item.detail then
                UIManager:show(InfoMessage:new{ text = item.detail, timeout = 8 })
            end
        end,
    }
    UIManager:show(menu)
end

function Hardcover:chooseBackupExportFolder()
    UIManager:show(PathChooser:new{
        title = _("Choose a folder for the Hardcover backup"),
        path = DataStorage:getDataDir(),
        select_directory = true,
        select_file = false,
        onConfirm = function(directory)
            local backup_path = directory .. "/hardcover-backup.json"
            local function writeBackup()
                local backup = {
                    schema_version = 1,
                    created_at = os.time(),
                    attachments = self.settings:readSetting("attachments") or {},
                    managed_collection_items = self.settings:readSetting("managed_collection_items") or {},
                    sync_status = self.settings:readSetting("sync_status") or {},
                }
                local ok, err = pcall(function()
                    local file = assert(io.open(backup_path, "w"))
                    assert(file:write(JSON.encode(backup)))
                    assert(file:close())
                end)
                if not ok then
                    self:recordDiagnostic("Backup export", err)
                    UIManager:show(InfoMessage:new{
                        text = T(_("Could not write backup: %1"), tostring(err)),
                        timeout = 8,
                    })
                    return
                end
                UIManager:show(InfoMessage:new{
                    text = T(_("Hardcover backup saved to:\n%1"), backup_path),
                    timeout = 6,
                })
            end
            if lfs.attributes(backup_path, "mode") == "file" then
                UIManager:show(ConfirmBox:new{
                    text = T(_("Replace existing backup?\n%1"), backup_path),
                    ok_text = _("Replace"),
                    ok_callback = writeBackup,
                })
            else
                writeBackup()
            end
        end,
    })
end

function Hardcover:restoreBackup(backup_path)
    local ok, backup = pcall(function()
        local file = assert(io.open(backup_path, "r"))
        local size = lfs.attributes(backup_path, "size") or 0
        if size > 5 * 1024 * 1024 then
            file:close()
            error(_("Backup file is too large."))
        end
        local content = file:read("*all")
        file:close()
        return JSON.decode(content)
    end)
    if not ok or type(backup) ~= "table" or backup.schema_version ~= 1
            or type(backup.attachments) ~= "table"
            or type(backup.managed_collection_items) ~= "table" then
        local message = ok and _("This is not a supported Hardcover backup.") or tostring(backup)
        self:recordDiagnostic("Backup restore", message)
        UIManager:show(InfoMessage:new{ text = message, timeout = 8 })
        return
    end

    local current_attachments = self.settings:readSetting("attachments") or {}
    local current_managed = self.settings:readSetting("managed_collection_items") or {}
    local restored, conflicts, missing = 0, 0, 0
    for book_id, path in pairs(backup.attachments) do
        if type(book_id) == "string" and type(path) == "string" then
            local canonical = ffiUtil.realpath(path)
            if canonical and lfs.attributes(canonical, "mode") == "file" then
                local current_path = current_attachments[book_id]
                if not current_path or lfs.attributes(current_path, "mode") ~= "file" then
                    current_attachments[book_id] = canonical
                    restored = restored + 1
                else
                    conflicts = conflicts + 1
                end
            else
                missing = missing + 1
            end
        else
            missing = missing + 1
        end
    end

    local added_to_collections = 0
    local collection_changed = false
    for name, paths in pairs(backup.managed_collection_items) do
        if type(name) == "string" and #name > 0 and #name <= 200 and type(paths) == "table" then
            if not ReadCollection.coll[name] then
                ReadCollection:addCollection(name)
                collection_changed = true
            end
            current_managed[name] = current_managed[name] or {}
            for path, is_managed in pairs(paths) do
                local canonical = type(path) == "string" and ffiUtil.realpath(path)
                if is_managed and canonical and lfs.attributes(canonical, "mode") == "file" then
                    local collection = ReadCollection.coll[name]
                    if not collection[canonical] then
                        ReadCollection:addItem(canonical, name)
                        if collection[canonical] then
                            added_to_collections = added_to_collections + 1
                            collection_changed = true
                        end
                    end
                    if collection[canonical] then
                        current_managed[name][canonical] = true
                    end
                elseif is_managed then
                    missing = missing + 1
                end
            end
        end
    end

    self.settings:saveSetting("attachments", current_attachments)
    self.settings:saveSetting("managed_collection_items", current_managed)
    if type(backup.sync_status) == "table" then
        local current_status = self.settings:readSetting("sync_status") or {}
        for key, value in pairs(backup.sync_status) do
            if current_status[key] == nil then current_status[key] = value end
        end
        self.settings:saveSetting("sync_status", current_status)
    end
    self.settings:flush()
    if collection_changed then ReadCollection:write() end

    local summary = T(_("Restored %1 attachments; added %2 collection entries; kept %3 existing attachment mappings; skipped %4 missing references."),
        restored, added_to_collections, conflicts, missing)
    self:recordSyncStatus("backup_restore", summary)
    UIManager:show(InfoMessage:new{ text = summary, timeout = 8 })
end

function Hardcover:chooseBackupImportFile()
    UIManager:show(PathChooser:new{
        title = _("Choose a Hardcover backup JSON file"),
        path = DataStorage:getDataDir(),
        select_directory = false,
        select_file = true,
        onConfirm = function(path)
            UIManager:show(ConfirmBox:new{
                text = _("Merge this backup with current Hardcover data? Existing valid attachments will be preserved."),
                ok_text = _("Restore"),
                ok_callback = function()
                    self:restoreBackup(path)
                end,
            })
        end,
    })
end

function Hardcover:scanStaleRecords()
    local issues = {}
    local stale_attachments = {}
    local missing_paths = {}
    local function isFile(path)
        return type(path) == "string" and lfs.attributes(path, "mode") == "file"
    end
    local function addIssue(text, detail, path)
        table.insert(issues, { text = text, detail = detail })
        if type(path) == "string" then missing_paths[path] = true end
    end

    local attachments = self.settings:readSetting("attachments") or {}
    for book_id, path in pairs(attachments) do
        if not isFile(path) then
            stale_attachments[tostring(book_id)] = path
            addIssue(
                T(_("Missing attached file for Hardcover book %1"), book_id),
                T(_("Book ID: %1\nMissing path: %2\nUse Detach file in the Hardcover book details to clear this record."),
                    book_id, tostring(path)),
                path
            )
        end
    end

    for collection_name, collection in pairs(ReadCollection.coll or {}) do
        for path in pairs(collection) do
            if not isFile(path) then
                addIssue(
                    T(_("Missing file in collection: %1"), collection_name),
                    T(_("Collection: %1\nMissing path: %2\nRemove this entry from File manager > Collections."),
                        collection_name, tostring(path)),
                    path
                )
            end
        end
    end

    if #issues == 0 then
        UIManager:show(InfoMessage:new{ text = _("No stale attachment or collection records found."), timeout = 5 })
        return
    end

    table.sort(issues, function(a, b) return a.text:lower() < b.text:lower() end)
    local items = {}
    if next(stale_attachments) then
        table.insert(items, {
            text = _("Find replacements for missing book files"),
            action = "relink",
        })
    end
    table.insert(items, {
        text = T(_("Repair all stale records (%1)"), #issues),
        action = "repair",
    })
    for _, issue in ipairs(issues) do
        table.insert(items, {
            text = issue.text,
            detail = issue.detail,
        })
    end
    local menu = Menu:new{
        title = T(_("Stale records found: %1"), #issues),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            if item.action == "relink" then
                self:findReplacementFiles(stale_attachments)
            elseif item.action == "repair" then
                UIManager:show(ConfirmBox:new{
                    text = _("Clear missing attachment paths and remove missing-file entries from collections? Local files will not be deleted."),
                    ok_text = _("Repair"),
                    ok_callback = function()
                        self:repairStaleRecords(stale_attachments, missing_paths)
                    end,
                })
            else
                UIManager:show(InfoMessage:new{ text = item.detail, timeout = 8 })
            end
        end,
    }
    UIManager:show(menu)
end

function Hardcover:repairStaleRecords(stale_attachments, missing_paths)
    local attachments = self.settings:readSetting("attachments") or {}
    local attachments_cleared = 0
    local settings_changed = false
    for book_id, old_path in pairs(stale_attachments) do
        local current_path = attachments[book_id]
        if current_path == old_path
                and (type(current_path) ~= "string" or lfs.attributes(current_path, "mode") ~= "file") then
            attachments[book_id] = nil
            attachments_cleared = attachments_cleared + 1
        end
    end
    if attachments_cleared > 0 then
        self.settings:saveSetting("attachments", attachments)
        settings_changed = true
    end

    local collection_entries_removed = 0
    local managed = self.settings:readSetting("managed_collection_items") or {}
    local managed_changed = false
    for path in pairs(missing_paths) do
        if type(path) == "string" and lfs.attributes(path, "mode") ~= "file" then
            for _, collection in pairs(ReadCollection.coll or {}) do
                if collection[path] then collection_entries_removed = collection_entries_removed + 1 end
            end
            if ReadCollection.coll then
                ReadCollection:removeItem(path, nil, true)
            end
            for _, collection_items in pairs(managed) do
                if collection_items[path] then
                    collection_items[path] = nil
                    managed_changed = true
                end
            end
        end
    end
    if collection_entries_removed > 0 then
        ReadCollection:write()
    end
    if managed_changed then
        self.settings:saveSetting("managed_collection_items", managed)
        settings_changed = true
    end
    if settings_changed then self.settings:flush() end

    UIManager:show(InfoMessage:new{
        text = T(_("Cleared %1 attachment records and removed %2 missing collection entries."),
            attachments_cleared, collection_entries_removed),
        timeout = 5,
    })
end

function Hardcover:promptForToken()
    local dialog
    dialog = InputDialog:new{
        title = _("Hardcover personal access token"),
        input = self:getToken() or "",
        input_type = "string",
        description = _("Enter a token created at hardcover.app > Settings > Developers"),
        buttons = {{
            {
                text = _("Cancel"),
                callback = function() UIManager:close(dialog) end,
            },
            {
                text = _("Save"),
                callback = function()
                    self.settings:saveSetting("access_token", dialog:getInputText())
                    self.settings:flush()
                    UIManager:close(dialog)
                end,
            },
        }},
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

-- -----------------------------------------------------------------: data ---

local DATA_DIR = DataStorage:getDataDir() .. "/hardcover"

local function saveJson(name, data)
    lfs.mkdir(DATA_DIR)
    local ok, err = pcall(function()
        local f = assert(io.open(DATA_DIR .. "/" .. name, "w"))
        assert(f:write(JSON.encode(data)))
        assert(f:close())
    end)
    if not ok then logger.err("Hardcover: cannot save", name, err) end
    return ok
end

function Hardcover:saveJson(name, data)
    if not saveJson(name, data) then
        self:recordDiagnostic("Cache", T(_("Could not save %1."), name))
        return
    end
    local timestamps = self.settings:readSetting("cache_timestamps") or {}
    timestamps[name] = os.time()
    self.settings:saveSetting("cache_timestamps", timestamps)
    self.settings:flush()
end

function Hardcover:loadJson(name)
    local path = DATA_DIR .. "/" .. name
    if lfs.attributes(path, "mode") ~= "file" then return nil end
    local ok, result = pcall(function()
        local f = assert(io.open(path, "r"))
        local content = f:read("*all")
        f:close()
        return JSON.decode(content)
    end)
    if not ok or type(result) ~= "table" then
        self:recordDiagnostic("Cache read", T(_("Could not read cached data: %1."), name))
        return nil
    end
    return result
end

--- My Hardcover lists. Returns array of {id, name, books_count} or nil.
function Hardcover:fetchLists()
    local data = self:query([[query { me { id lists { id name books_count } } }]])
    local me = data and data.me and data.me[1]
    if not me then return nil end
    local lists = me.lists or {}
    self:saveJson("lists.json", lists)
    return lists
end

--- My series trackers (followed series). Returns array of {id, name, books_count} or nil.
function Hardcover:fetchSeries()
    local data = self:query([[query { me {
        follows (where: {followable_type: {_eq: "Series"}}) {
            id series { id name books_count primary_books_count } } } }]])
    local me = data and data.me and data.me[1]
    if not me then return nil end
    local follows = me.follows or {}
    local series = {}
    for _, f in ipairs(follows) do
        if f.series then table.insert(series, f.series) end
    end
    self:saveJson("series.json", series)
    return series
end

--- Books of a list, with full details. Returns array of book tables or nil.
local BOOKS_QUERY = [[query {
    me {
        lists(where: {id: {_eq: %d}}) {
            name
            list_books {
                book {
                    id title rating release_date
                    contributions { contribution author { name } }
                    editions(limit: 5) {
                        title isbn_10 isbn_13 physical_format pages language { code2 }
                    }
                }
            }
        }
    }
}]]

function Hardcover:fetchListBooks(list)
    local data = self:query(BOOKS_QUERY:format(list.id))
    local me = data and data.me and data.me[1]
    if not me then return nil end
    local l = me.lists and me.lists[1]
    if not l then return nil end
    local books = {}
    for _, lb in ipairs(l.list_books or {}) do
        if lb.book then table.insert(books, lb.book) end
    end
    self:saveJson(("list_%d_books.json"):format(list.id), books)
    return books
end

--- Books of a followed series. Returns array of book tables or nil.
-- Note: the API exposes no series->books field; books are matched via
-- book_series, and we keep the same "me.follows[1].series.books" result shape.
function Hardcover:fetchSeriesBooks(series)
    local series_id = series.id or (series.series and series.series.id)
    if not series_id then return nil end
    local data = self:query(([[
    query {
        books(where: {book_series: {series_id: {_eq: %d}}},
              order_by: {release_date: asc, id: asc}, limit: 50) {
            id title rating release_date
            book_series(where: {series_id: {_eq: %d}}) {
                position compilation
            }
            contributions { contribution author { name } }
            editions(limit: 5) {
                title isbn_10 isbn_13 physical_format pages language { code2 }
            }
            english_editions: editions(
                where: {language: {code2: {_eq: "en"}}}, limit: 1
            ) { id }
        }
    }]]):format(series_id, series_id))
    local raw_books = data and data.books
    if not raw_books then return nil end

    local books_by_position = {}
    for _, book in ipairs(raw_books) do
        local membership = book.book_series and book.book_series[1]
        local position = membership and tonumber(membership.position)
        if position and position > 0 and position == math.floor(position) and not membership.compilation then
            local current = books_by_position[position]
            local has_english_edition = book.english_editions and #book.english_editions > 0
            local current_has_english = current and current.english_editions
                and #current.english_editions > 0
            if not current or (has_english_edition and not current_has_english) then
                books_by_position[position] = book
            end
        end
    end

    local positions = {}
    for position in pairs(books_by_position) do
        table.insert(positions, position)
    end
    table.sort(positions)

    local primary_count = tonumber(series.primary_books_count)
    if primary_count and #positions < primary_count then
        logger.warn("Hardcover: fewer positioned books than primary_books_count for series", series_id)
    end
    local books = {}
    for index, position in ipairs(positions) do
        if primary_count and index > primary_count then break end
        local book = books_by_position[position]
        book.series_number = position
        table.insert(books, book)
    end

    self:saveJson(("series_%d_books.json"):format(series_id), books)
    return books
end

-- ------------------------------------------------------: collections view --

local function collectionName(list_name)
    return COLLECTION_PREFIX .. (list_name or "?")
end

local function metadataText(value)
    if type(value) == "string" then
        return value
    elseif type(value) == "number" then
        return tostring(value)
    elseif value ~= nil then
        logger.warn("Hardcover: ignoring non-scalar book metadata", type(value))
    end
end

local function bookAuthors(book)
    local author
    for _, c in ipairs(book.contributions or {}) do
        local name = c.author and metadataText(c.author.name)
        if name then
            author = (author and author .. ", " or "") .. name
        end
    end
    return author
end

local function seriesCollectionName(series, books)
    local author
    for _, book in ipairs(books or {}) do
        author = bookAuthors(book)
        if author then break end
    end
    return (author and (author .. " - ") or "") .. (metadataText(series.name) or "?")
end

function Hardcover:getCachedPendingCollectionChanges()
    local additions, removals = 0, 0
    local managed = self.settings:readSetting("managed_collection_items") or {}
    local function countChanges(name, books)
        local desired = {}
        for _, book in ipairs(books or {}) do
            local path = self:getAttachment(book.id)
            local canonical = type(path) == "string" and ffiUtil.realpath(path)
            if canonical and lfs.attributes(canonical, "mode") == "file" then
                desired[canonical] = true
            end
        end
        local current = ReadCollection.coll[name] or {}
        for path in pairs(desired) do
            if not current[path] then additions = additions + 1 end
        end
        for path in pairs(managed[name] or {}) do
            if current[path] and not desired[path] then removals = removals + 1 end
        end
    end
    for _, list in ipairs(self:loadJson("lists.json") or {}) do
        countChanges(collectionName(list.name),
            self:loadJson(("list_%d_books.json"):format(list.id)) or {})
    end
    for _, series in ipairs(self:loadJson("series.json") or {}) do
        local series_id = series.id or (series.series and series.series.id)
        if series_id then
            local books = self:loadJson(("series_%d_books.json"):format(series_id)) or {}
            countChanges(seriesCollectionName(series, books), books)
        end
    end
    return additions, removals
end

function Hardcover:retryCollectionRefresh(retry)
    if retry.type == "progress" then
        self:syncReadingProgress()
    elseif retry.type == "list" then
        NetworkMgr:goOnlineToRun(function()
            local lists = self:fetchLists()
            for _, list in ipairs(lists or {}) do
                if tostring(list.id) == tostring(retry.id) then
                    local books = self:fetchListBooks(list)
                    if books then
                        self:showCollectionRefreshPreview(collectionName(list.name), books)
                    end
                    return
                end
            end
            UIManager:show(InfoMessage:new{ text = _("The Hardcover list is no longer available."), timeout = 5 })
        end)
    elseif retry.type == "series" then
        NetworkMgr:goOnlineToRun(function()
            local series_list = self:fetchSeries()
            for _, series in ipairs(series_list or {}) do
                if tostring(series.id) == tostring(retry.id) then
                    local books = self:fetchSeriesBooks(series)
                    if books then
                        self:showCollectionRefreshPreview(seriesCollectionName(series, books), books)
                    end
                    return
                end
            end
            UIManager:show(InfoMessage:new{ text = _("The Hardcover series is no longer available."), timeout = 5 })
        end)
    end
end

function Hardcover:markManagedCollectionItem(collection_name, file)
    local managed = self.settings:readSetting("managed_collection_items") or {}
    managed[collection_name] = managed[collection_name] or {}
    managed[collection_name][file] = true
    self.settings:saveSetting("managed_collection_items", managed)
end

--- Ensure an attached book's file is a member of a collection.
function Hardcover:attachToCollection(book, coll)
    local file = self:getAttachment(book.id)
    local canonical_file = type(file) == "string" and ffiUtil.realpath(file)
    local collection = ReadCollection.coll and ReadCollection.coll[coll]
    if canonical_file and collection and lfs.attributes(canonical_file, "mode") == "file"
            and not collection[canonical_file] then
        ReadCollection:addItem(canonical_file, coll)
        if collection[canonical_file] then
            self:markManagedCollectionItem(coll, canonical_file)
            return true
        end
    end
    return false
end

local function cachedBooksContain(books, book_id)
    for _, cached_book in ipairs(books or {}) do
        if tostring(cached_book.id) == tostring(book_id) then return true end
    end
    return false
end

--- Create/refresh KOReader collections from Hardcover lists (idempotent).
function Hardcover:syncListsToCollections()
    NetworkMgr:goOnlineToRun(function()
        local lists = self:fetchLists()
        if not lists then
            local message = self.last_query_error or _("Failed to fetch lists.")
            self:recordSyncStatus("lists", message, true)
            self:recordDiagnostic("List collection sync", message)
            return
        end
        local created, attached = 0, 0
        local failures = {}
        for _, list in ipairs(lists) do
            local books = self:fetchListBooks(list)
            if not books then
                local name = metadataText(list.name) or tostring(list.id)
                local message = T(_("Could not fetch books for list: %1"), name)
                table.insert(failures, message)
                self:recordDiagnostic("List collection sync", message, {
                    type = "list",
                    id = list.id,
                })
            else
                local coll = collectionName(list.name)
                if not (ReadCollection.coll and ReadCollection.coll[coll]) then
                    ReadCollection:addCollection(coll)
                    created = created + 1
                end
                for _, book in ipairs(books) do
                    if self:attachToCollection(book, coll) then
                        attached = attached + 1
                    end
                end
            end
        end
        ReadCollection:write()
        self.settings:flush()
        local summary = T(_("%1 lists; %2 new collections; %3 attached books added; %4 failed."),
            #lists, created, attached, #failures)
        self:recordSyncStatus("lists", summary, #failures > 0)
        UIManager:show(InfoMessage:new{
            text = T(_("Synced %1\n%2\nFind them in File manager > Collections."),
                summary, table.concat(failures, "\n")),
            timeout = 5,
        })
    end)
end

--- Create/refresh KOReader collections from followed series (idempotent).
function Hardcover:syncSeriesToCollections()
    NetworkMgr:goOnlineToRun(function()
        local series_list = self:fetchSeries()
        if not series_list then
            local message = self.last_query_error or _("Failed to fetch series trackers.")
            self:recordSyncStatus("series", message, true)
            self:recordDiagnostic("Series collection sync", message)
            return
        end
        local created, attached = 0, 0
        local failures = {}
        for _, series in ipairs(series_list) do
            local books = self:fetchSeriesBooks(series)
            if not books then
                local message = T(_("Could not fetch books for series: %1"),
                    metadataText(series.name) or tostring(series.id))
                table.insert(failures, message)
                self:recordDiagnostic("Series collection sync", message, {
                    type = "series",
                    id = series.id,
                })
            else
                local coll = seriesCollectionName(series, books)
                if not (ReadCollection.coll and ReadCollection.coll[coll]) then
                    ReadCollection:addCollection(coll)
                    created = created + 1
                end
                for _, book in ipairs(books) do
                    if self:attachToCollection(book, coll) then
                        attached = attached + 1
                    end
                end
            end
        end
        ReadCollection:write()
        self.settings:flush()
        local summary = T(_("%1 series trackers; %2 new collections; %3 attached books added; %4 failed."),
            #series_list, created, attached, #failures)
        self:recordSyncStatus("series", summary, #failures > 0)
        UIManager:show(InfoMessage:new{
            text = T(_("Synced %1\n%2\nFind them in File manager > Collections."),
                summary, table.concat(failures, "\n")),
            timeout = 5,
        })
    end)
end

--- Add a newly attached book to any existing Hardcover-mirrored collections.
function Hardcover:attachToMirroredCollections(book)
    local added = 0
    for _, list in ipairs(self:loadJson("lists.json") or {}) do
        local books = self:loadJson(("list_%d_books.json"):format(list.id))
        if cachedBooksContain(books, book.id) then
            if self:attachToCollection(book, collectionName(list.name)) then added = added + 1 end
        end
    end
    for _, series in ipairs(self:loadJson("series.json") or {}) do
        local books = self:loadJson(("series_%d_books.json"):format(series.id)) or {}
        if cachedBooksContain(books, book.id) then
            if self:attachToCollection(book, seriesCollectionName(series, books)) then added = added + 1 end
        end
    end
    if added > 0 then
        ReadCollection:write()
        self.settings:flush()
    end
end

function Hardcover:applyCollectionRefresh(collection_name, desired_files, removals)
    if not ReadCollection.coll[collection_name] then
        ReadCollection:addCollection(collection_name)
    end
    local collection = ReadCollection.coll[collection_name]
    local managed = self.settings:readSetting("managed_collection_items") or {}
    managed[collection_name] = managed[collection_name] or {}
    local added, removed = 0, 0

    if removals then
        for file in pairs(managed[collection_name]) do
            if not desired_files[file] then
                if collection[file] then
                    ReadCollection:removeItem(file, collection_name, true)
                    removed = removed + 1
                end
                managed[collection_name][file] = nil
            end
        end
    end

    for file in pairs(desired_files) do
        if not collection[file] and lfs.attributes(file, "mode") == "file" then
            ReadCollection:addItem(file, collection_name)
            if collection[file] then
                managed[collection_name][file] = true
                added = added + 1
            end
        end
    end

    self.settings:saveSetting("managed_collection_items", managed)
    self.settings:flush()
    ReadCollection:write()
    return added, removed
end

function Hardcover:showCollectionRefreshPreview(collection_name, books)
    local desired_files = {}
    local attachment_missing = 0
    for _, book in ipairs(books) do
        local path = self:getAttachment(book.id)
        if path then
            local canonical = type(path) == "string" and ffiUtil.realpath(path)
            if canonical and lfs.attributes(canonical, "mode") == "file" then
                desired_files[canonical] = true
            else
                attachment_missing = attachment_missing + 1
            end
        end
    end

    local current = ReadCollection.coll[collection_name] or {}
    local managed = (self.settings:readSetting("managed_collection_items") or {})[collection_name] or {}
    local additions, removals = {}, {}
    for file in pairs(desired_files) do
        if not current[file] then table.insert(additions, file) end
    end
    for file in pairs(managed) do
        if not desired_files[file] and current[file] then
            table.insert(removals, file)
        end
    end
    table.sort(additions)
    table.sort(removals)

    if #additions == 0 and #removals == 0 then
        UIManager:show(InfoMessage:new{
            text = T(_("No mirrored changes for %1. Manual collection entries are preserved."),
                collection_name),
            timeout = 5,
        })
        return
    end

    local items = {
        {
            text = T(_("Apply %1 additions and %2 outdated mirrored removals"),
                #additions, #removals),
            action = "apply",
        },
        {
            text = T(_("Add only (%1 files); keep existing entries"), #additions),
            action = "add",
        },
        {
            text = _("Preview: additions"),
            dim = true,
        },
    }
    for _, file in ipairs(additions) do
        table.insert(items, {
            text = "+ " .. file:match("([^/]+)$"),
            detail = file,
            dim = true,
        })
    end
    if #removals > 0 then
        table.insert(items, { text = _("Preview: outdated mirrored entries"), dim = true })
        for _, file in ipairs(removals) do
            table.insert(items, {
                text = "- " .. file:match("([^/]+)$"),
                detail = file,
                dim = true,
            })
        end
    end
    if attachment_missing > 0 then
        table.insert(items, {
            text = T(_("%1 missing attachments were excluded"), attachment_missing),
            dim = true,
        })
    end

    local menu = Menu:new{
        title = T(_("Refresh preview: %1"), collection_name),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            if item.action == "add" then
                local added = self:applyCollectionRefresh(collection_name, desired_files, false)
                self:recordSyncStatus("collection_refresh", T(_("%1 additions applied to %2; removals preserved."),
                    added, collection_name))
                UIManager:show(InfoMessage:new{
                    text = T(_("Added %1 books to %2. Existing entries were preserved."), added, collection_name),
                    timeout = 5,
                })
            elseif item.action == "apply" then
                UIManager:show(ConfirmBox:new{
                    text = T(_("Apply %1 additions and remove %2 outdated mirrored entries from %3? Manually added entries will be preserved."),
                        #additions, #removals, collection_name),
                    ok_text = _("Apply"),
                    ok_callback = function()
                        local added, removed = self:applyCollectionRefresh(collection_name, desired_files, true)
                        self:recordSyncStatus("collection_refresh", T(_("%1 additions and %2 removals applied to %3."),
                            added, removed, collection_name))
                        UIManager:show(InfoMessage:new{
                            text = T(_("Added %1 books and removed %2 outdated mirrored entries from %3."),
                                added, removed, collection_name),
                            timeout = 5,
                        })
                    end,
                })
            elseif item.detail then
                UIManager:show(InfoMessage:new{ text = item.detail, timeout = 5 })
            end
        end,
    }
    UIManager:show(menu)
end

function Hardcover:browseCollectionsForRefresh()
    NetworkMgr:goOnlineToRun(function()
        local lists = self:fetchLists()
        local series_list = self:fetchSeries()
        if not lists or not series_list then
            local message = self.last_query_error or _("Could not load Hardcover collections.")
            self:recordSyncStatus("collection_refresh", message, true)
            self:recordDiagnostic("Collection refresh", message)
            return
        end

        local items = {}
        for _, list in ipairs(lists) do
            table.insert(items, {
                text = T(_("List: %1"), metadataText(list.name) or "?"),
                list = list,
            })
        end
        for _, series in ipairs(series_list) do
            table.insert(items, {
                text = T(_("Series: %1"), metadataText(series.name) or "?"),
                series = series,
            })
        end
        if #items == 0 then
            UIManager:show(InfoMessage:new{ text = _("No Hardcover lists or series found."), timeout = 5 })
            return
        end
        local menu = Menu:new{
            title = _("Choose a collection to refresh"),
            item_table = items,
            onMenuSelect = function(self_menu, item)
                NetworkMgr:goOnlineToRun(function()
                    if item.list then
                        local books = self:fetchListBooks(item.list)
                        if books then
                            self:showCollectionRefreshPreview(collectionName(item.list.name), books)
                        else
                            local message = self.last_query_error
                                or T(_("Could not load books from list: %1"), metadataText(item.list.name) or "?")
                            self:recordSyncStatus("collection_refresh", message, true)
                            self:recordDiagnostic("List: " .. (metadataText(item.list.name) or "?"), message, {
                                type = "list",
                                id = item.list.id,
                            })
                        end
                    else
                        local books = self:fetchSeriesBooks(item.series)
                        if books then
                            self:showCollectionRefreshPreview(seriesCollectionName(item.series, books), books)
                        else
                            local message = self.last_query_error
                                or T(_("Could not load books from series: %1"), metadataText(item.series.name) or "?")
                            self:recordSyncStatus("collection_refresh", message, true)
                            self:recordDiagnostic("Series: " .. (metadataText(item.series.name) or "?"), message, {
                                type = "series",
                                id = item.series.id,
                            })
                        end
                    end
                end)
            end,
        }
        UIManager:show(menu)
    end)
end

--- -----------------------------------------------------------------: UI -----

--- Book label, optionally prefixed with its series name and series-list number.
local function bookText(book, series_name, series_number)
    if series_name then
        return ("%s[%s]-%s"):format(
            series_name, tostring(book.series_number or series_number), metadataText(book.title) or "?"
        )
    end
    local author = bookAuthors(book)
    return ("%s%s"):format(metadataText(book.title) or "?", author and (" — " .. author) or "")
end

local function setMenuSearch(menu, items, search_text, include_item)
    menu.search_callback = function(search_string)
        local needle = (search_string or ""):lower()
        local filtered = {}
        for _, item in ipairs(items) do
            local is_included = not include_item or include_item(item)
            local matches_search = item.filter_control or needle == ""
                or search_text(item):lower():find(needle, 1, true)
            if is_included and matches_search then
                table.insert(filtered, item)
            end
        end
        menu:switchItemTable(nil, filtered)
    end
end

local function localReadingProgress(path)
    if type(path) ~= "string" or lfs.attributes(path, "mode") ~= "file" then
        return nil
    end
    local doc_settings = DocSettings:open(path)
    local percent = tonumber(doc_settings:readSetting("percent_finished"))
    local local_pages = tonumber(doc_settings:readSetting("doc_pages"))
    local pages = doc_settings:isTrue("pagemap_use_page_labels")
        and tonumber(doc_settings:readSetting("pagemap_doc_pages"))
        or local_pages
    if not pages or pages <= 0 then
        local stats = doc_settings:readSetting("stats")
        pages = stats and tonumber(stats.pages)
        local_pages = local_pages or pages
    end
    if not pages or pages <= 0 then return nil end
    if percent == nil then return nil, pages, local_pages or pages end
    return math.max(0, math.min(1, percent)), pages, local_pages or pages
end

local function bookLocalStatus(self, book)
    local path = self:getAttachment(book.id)
    if not path or lfs.attributes(path, "mode") ~= "file" then return "unattached" end
    local percent = localReadingProgress(path)
    if not percent or percent <= 0 then return "unread" end
    if percent >= 0.99 then return "finished" end
    return "in_progress"
end

--- Multi-line details text for a book (shown before any attachment).
local function bookDetailsText(book)
    local lines = { metadataText(book.title) or "?" }
    local author = bookAuthors(book)
    if author then table.insert(lines, _("by") .. " " .. author) end
    local rating = tonumber(book.rating)
    if rating then
        table.insert(lines, ("Rating: %.2f"):format(rating))
    elseif book.rating ~= nil then
        logger.warn("Hardcover: ignoring non-numeric book rating", type(book.rating))
    end
    local release_date = metadataText(book.release_date)
    if release_date then table.insert(lines, _("Released:") .. " " .. release_date) end
    if book.hardcover_sources and #book.hardcover_sources > 0 then
        table.insert(lines, _("Hardcover lists/series:") .. " " .. table.concat(book.hardcover_sources, ", "))
    end
    for index, ed in ipairs(book.editions or {}) do
        local parts = {}
        local physical_format = metadataText(ed.physical_format)
        local language = ed.language and metadataText(ed.language.code2)
        local pages = tonumber(ed.pages)
        if physical_format then table.insert(parts, physical_format) end
        if language then table.insert(parts, language:upper()) end
        if pages then table.insert(parts, T(_("%1 pages"), pages)) end
        if ed.isbn_13 then
            table.insert(parts, "ISBN " .. tostring(ed.isbn_13))
        elseif ed.isbn_10 then
            table.insert(parts, "ISBN " .. tostring(ed.isbn_10))
        end
        if #parts > 0 then
            table.insert(lines, T(_("Edition %1: %2"), index, table.concat(parts, " · ")))
        end
    end
    return table.concat(lines, "\n")
end

--- Browse books inside a full-screen Menu; tapping a book shows its details.
function Hardcover:showBooksMenu(books, title, series_name)
    local book_items = {}
    for index, book in ipairs(books) do
        local label = bookText(book, series_name, index)
        local status = bookLocalStatus(self, book)
        local attached = status ~= "unattached"
        local sources = book.hardcover_sources and (" " .. table.concat(book.hardcover_sources, " "))
            or ""
        table.insert(book_items, {
            text = label,
            mandatory = status == "unattached" and _("No file")
                or status == "unread" and _("Unread")
                or status == "finished" and _("Finished")
                or _("In progress"),
            mandatory_dim = status == "unattached",
            search_text = label .. sources .. " " .. status,
            attached = attached,
            local_status = status,
            sort_title = (metadataText(book.title) or "?"):lower(),
            original_index = index,
            book = book,
        })
    end
    local sort_mode = self.settings:readSetting("book_sort_mode") or "hardcover"
    if sort_mode == "title" then
        table.sort(book_items, function(a, b)
            if a.sort_title == b.sort_title then return a.original_index < b.original_index end
            return a.sort_title < b.sort_title
        end)
    elseif sort_mode == "attached" then
        table.sort(book_items, function(a, b)
            if a.attached ~= b.attached then return a.attached end
            if a.sort_title == b.sort_title then return a.original_index < b.original_index end
            return a.sort_title < b.sort_title
        end)
    end
    local active_filter = "all"
    local filter_item = {
        text = _("Filter: All books"),
        mandatory = _("Change"),
        filter_control = true,
        search_text = "",
    }
    local items = { filter_item }
    for _, item in ipairs(book_items) do table.insert(items, item) end
    local filter_labels = {
        all = _("All books"),
        unattached = _("No local file"),
        unread = _("Unread / not started"),
        in_progress = _("In progress"),
        finished = _("Finished"),
    }
    local menu
    menu = Menu:new{
        title = title,
        item_table = items,
        is_borderless = false,
        is_popout = false,
        onMenuSelect = function(self_menu, item)
            if item.filter_control then
                local filter_dialog
                local buttons = {}
                for _, option in ipairs({ "all", "unattached", "unread", "in_progress", "finished" }) do
                    local selected_option = option
                    table.insert(buttons, {{
                        text = filter_labels[selected_option],
                        callback = function()
                            active_filter = selected_option
                            filter_item.text = T(_("Filter: %1"), filter_labels[selected_option])
                            UIManager:close(filter_dialog)
                            menu.search_callback("")
                        end,
                    }})
                end
                filter_dialog = ButtonDialog:new{
                    title = _("Filter books by local reading status"),
                    buttons = buttons,
                }
                UIManager:show(filter_dialog)
            else
                self:showBookDetails(item.book)
            end
        end,
    }
    setMenuSearch(menu, items, function(item) return item.search_text end, function(item)
        return item.filter_control or active_filter == "all" or item.local_status == active_filter
    end)
    UIManager:show(menu)
end

--- Show all book details; "Read" if a file is attached, else "Attach a file".
function Hardcover:showBookDetails(book, suggestions)
    local attached_file = self:getAttachment(book.id)
    local details = bookDetailsText(book)
    if suggestions and #suggestions > 0 then
        local candidate_lines = { _("Local file candidates:") }
        for index, suggestion in ipairs(suggestions) do
            table.insert(candidate_lines, T(_("%1. %2\n%3"),
                index, suggestion.label or _("Possible match"), suggestion.path))
        end
        details = details .. "\n\n" .. table.concat(candidate_lines, "\n")
    end
    local attachment_exists = attached_file and lfs.attributes(attached_file, "mode") == "file"
    if attached_file and not attachment_exists then
        details = details .. "\n\n" .. T(_("Missing local file: %1"), attached_file)
    end
    local file_name = attached_file and attached_file:match("([^/]+)$")

    local buttons = {}
    if attachment_exists then
        table.insert(buttons, {{
            text = _("Read") .. (file_name and ("  (" .. file_name .. ")") or ""),
            callback = function()
                UIManager:close(self.details_dialog)
                filemanagerutil.openFile(self.ui, attached_file)
            end,
        }})
        table.insert(buttons, {{
            text = _("Detach file"),
            callback = function()
                self:setAttachment(book.id, nil)
                UIManager:close(self.details_dialog)
                self:showBookDetails(book)
            end,
        }})
    else
        for _, suggestion in ipairs(suggestions or {}) do
            local candidate = suggestion
            table.insert(buttons, {{
                text = T(_("Attach %1 (%2, %3%%)"),
                    candidate.path:match("([^/]+)$"), candidate.label or _("local file"), candidate.score),
                callback = function()
                    if lfs.attributes(candidate.path, "mode") ~= "file" then
                        UIManager:show(InfoMessage:new{
                            text = _("The suggested file is no longer available. Scan the folder again."),
                            timeout = 5,
                        })
                        return
                    end
                    UIManager:close(self.details_dialog)
                    self:setAttachment(book.id, candidate.path)
                    self:attachToMirroredCollections(book)
                    self:showBookDetails(book)
                end,
            }})
        end
        table.insert(buttons, {{
            text = _("Attach a file"),
            callback = function()
                UIManager:close(self.details_dialog)
                self:chooseAttachment(book)
            end,
        }})
    end

    self.details_dialog = ButtonDialog:new{
        title = details,
        title_align = "center",
        buttons = buttons,
        dismissable = true,
    }
    UIManager:show(self.details_dialog)
end

--- PathChooser flow to attach a local file to a book.
local function readableDirectory(path)
    if type(path) ~= "string" or path == "" then return nil end
    local real_path = ffiUtil.realpath(path)
    if not real_path or lfs.attributes(real_path, "mode") ~= "directory" then return nil end
    local ok = pcall(function()
        for _ in lfs.dir(real_path) do end
    end)
    return ok and real_path or nil
end

function Hardcover:chooseAttachment(book)
    local candidates = {}
    local function addCandidate(path)
        if path then candidates[#candidates + 1] = path end
    end
    addCandidate(G_reader_settings:readSetting("home_dir"))
    addCandidate(G_reader_settings:readSetting("lastdir"))
    addCandidate(Device.home_dir)
    addCandidate(DataStorage:getDataDir())
    addCandidate("/")

    local path
    for _, candidate in ipairs(candidates) do
        path = readableDirectory(candidate)
        if path then break end
    end
    if not path then
        UIManager:show(InfoMessage:new{
            text = _("No readable folder found. Set a readable File Manager home folder and try again."),
            timeout = 5,
        })
        return
    end

    local chooser = PathChooser:new{
        path = path,
        select_directory = false,
        onConfirm = function(file)
            self:setAttachment(book.id, file)
            self:attachToMirroredCollections(book)
            UIManager:show(InfoMessage:new{
                text = T(_("Attached:\n%1"), file),
                timeout = 3,
            })
            self:showBookDetails(book)
        end,
    }
    UIManager:show(chooser)
end

local function normalizeMatchText(value)
    if type(value) ~= "string" then return "" end
    return value:lower():gsub("[%p%s]", "")
end

local function extractIsbns(value, result)
    if type(value) == "string" or type(value) == "number" then
        for candidate in tostring(value):upper():gmatch("[%dX%-]+") do
            local isbn = candidate:gsub("[^%dX]", "")
            if #isbn == 10 or #isbn == 13 then result[isbn] = true end
        end
    elseif type(value) == "table" then
        for _, child in pairs(value) do
            extractIsbns(child, result)
        end
    end
end

local function localMetadataText(value)
    if type(value) == "string" or type(value) == "number" then
        return tostring(value)
    elseif type(value) == "table" then
        local parts = {}
        for _, child in pairs(value) do
            local text = localMetadataText(child)
            if text then table.insert(parts, text) end
        end
        return #parts > 0 and table.concat(parts, ", ") or nil
    end
end

local function getLocalBookMetadata(path)
    local filename = path:match("([^/]+)$") or path
    local filename_title = filename:gsub("%.[^%.]+$", "")
    local extension = filename:match("%.([^%.]+)$")
    local props
    local ok, settings = pcall(function() return DocSettings:open(path) end)
    if ok and settings then
        props = settings:readSetting("doc_props")
    end
    local metadata_error = not ok

    if type(props) ~= "table" or not props.title or not props.authors or not props.identifiers then
        local document
        local opened, document_props = pcall(function()
            document = DocumentRegistry:openDocument(path)
            if not document then return nil end
            if document.loadDocument and not document:loadDocument(false) then return nil end
            return document:getProps()
        end)
        if document then pcall(function() document:close() end) end
        if opened and type(document_props) == "table" then
            props = props or {}
            for key, value in pairs(document_props) do
                if props[key] == nil then props[key] = value end
            end
        elseif not opened then
            metadata_error = true
        end
    end

    local isbns = {}
    extractIsbns(props and props.identifiers, isbns)
    local attributes = lfs.attributes(path) or {}
    return {
        path = path,
        title = localMetadataText(props and props.title) or filename_title,
        authors = localMetadataText(props and props.authors) or "",
        isbns = isbns,
        format = extension and extension:upper() or _("Unknown format"),
        language = localMetadataText(props and props.language) or _("Unknown language"),
        pages = settings and tonumber(settings:readSetting("doc_pages")),
        size = tonumber(attributes.size),
    }, metadata_error
end

local function matchLocalBook(hardcover_book, local_book)
    local hardcover_isbns = {}
    local same_language = false
    for _, edition in ipairs(hardcover_book.editions or {}) do
        extractIsbns(edition.isbn_10, hardcover_isbns)
        extractIsbns(edition.isbn_13, hardcover_isbns)
        local hardcover_language = edition.language and edition.language.code2
        if type(hardcover_language) == "string" and type(local_book.language) == "string"
                and hardcover_language:lower() == local_book.language:lower() then
            same_language = true
        end
    end
    for isbn in pairs(hardcover_isbns) do
        if local_book.isbns[isbn] then
            return 100
        end
    end

    local hardcover_title_text = metadataText(hardcover_book.title) or ""
    local hardcover_title = normalizeMatchText(hardcover_title_text)
    local local_title = normalizeMatchText(local_book.title)
    local score = 0
    if hardcover_title ~= "" and local_title ~= "" then
        if hardcover_title == local_title then
            score = 70
        elseif #hardcover_title >= 5 and #local_title >= 5
                and (hardcover_title:find(local_title, 1, true)
                    or local_title:find(hardcover_title, 1, true)) then
            score = 50
        else
            local title_tokens = {}
            local local_tokens = {}
            for token in hardcover_title_text:lower():gmatch("[%w]+") do
                if #token > 2 then title_tokens[token] = true end
            end
            for token in local_book.title:lower():gmatch("[%w]+") do
                if #token > 2 then local_tokens[token] = true end
            end
            local shared, total = 0, 0
            for token in pairs(title_tokens) do
                total = total + 1
                if local_tokens[token] then shared = shared + 1 end
            end
            if total > 0 and shared / total >= 0.75 then score = 50 end
        end
    end

    local hardcover_author = normalizeMatchText(bookAuthors(hardcover_book) or "")
    local local_author = normalizeMatchText(local_book.authors)
    if hardcover_author ~= "" and local_author ~= "" then
        if hardcover_author == local_author then
            score = score + 25
        elseif hardcover_author:find(local_author, 1, true)
                or local_author:find(hardcover_author, 1, true) then
            score = score + 15
        end
    end
    if same_language then score = score + 10 end
    return score >= 55 and score or nil
end

function Hardcover:showSmartMatchMenu(books, local_books, unreadable_dirs, metadata_errors)
    local items = {}
    local suggested_count = 0
    for _, book in ipairs(books) do
        local matches = {}
        for _, local_book in ipairs(local_books) do
            local score = matchLocalBook(book, local_book)
            if score then
                table.insert(matches, { path = local_book.path, score = score })
            end
        end
        table.sort(matches, function(a, b)
            if a.score == b.score then return a.path < b.path end
            return a.score > b.score
        end)
        while #matches > 3 do table.remove(matches) end
        for _, match in ipairs(matches) do
            local candidate
            for _, local_book in ipairs(local_books) do
                if local_book.path == match.path then
                    candidate = local_book
                    break
                end
            end
            if candidate then
                local size = candidate.size
                    and T(_("%1 bytes"), util.getFormattedSize(candidate.size))
                local label_parts = {
                    candidate.format or _("Unknown format"),
                    candidate.language or _("Unknown language"),
                    size or _("size unknown"),
                }
                if candidate.pages then
                    table.insert(label_parts, T(_("%1 pages"), candidate.pages))
                end
                local isbn = next(candidate.isbns or {})
                if isbn then table.insert(label_parts, "ISBN " .. isbn) end
                match.label = table.concat(label_parts, " · ")
            end
        end
        if #matches > 0 then suggested_count = suggested_count + 1 end
        local best_match = matches[1]
        local book_label = bookText(book)
        table.insert(items, {
            text = book_label,
            mandatory = best_match
                and T(_("%1%%: %2"), best_match.score, best_match.path:match("([^/]+)$"))
                or _("No match"),
            search_text = book_label .. " " .. (best_match and best_match.path or ""),
            book = book,
            matches = matches,
        })
    end

    if suggested_count == 0 then
        UIManager:show(InfoMessage:new{
            text = _("No likely local matches found. You can still attach books manually from Books still to attach."),
            timeout = 6,
        })
        return
    end

    local title = T(_("Review %1 suggested matches for %2 books"),
        suggested_count, #books)
    if unreadable_dirs > 0 or metadata_errors > 0 then
        title = title .. "\n" .. T(_("Skipped folders: %1; metadata issues: %2"),
            unreadable_dirs, metadata_errors)
    end
    local menu = Menu:new{
        title = title,
        item_table = items,
        is_borderless = false,
        is_popout = false,
        onMenuSelect = function(self_menu, item)
            self:showBookDetails(item.book, item.matches)
        end,
    }
    setMenuSearch(menu, items, function(item) return item.search_text end)
    UIManager:show(menu)
end

function Hardcover:scanLocalFolderForMatches(root, books)
    local info = InfoMessage:new{ text = _("Scanning supported books… (tap to cancel)") }
    UIManager:show(info)
    UIManager:forceRePaint()

    local completed, local_books, unreadable_dirs, metadata_errors =
        Trapper:dismissableRunInSubprocess(function()
            local candidates = {}
            local visited = {}
            local unreadable = 0
            local metadata_failed = 0
            local excluded_dirs = {
                ["/dev"] = true,
                ["/proc"] = true,
                ["/sys"] = true,
                ["/mnt/base-us"] = true,
            }
            local function visit(directory)
                local canonical = ffiUtil.realpath(directory)
                if not canonical then
                    unreadable = unreadable + 1
                    return
                end
                if visited[canonical] or excluded_dirs[canonical] then return end
                visited[canonical] = true
                local ok, iter, dir_obj = pcall(lfs.dir, canonical)
                if not ok then
                    unreadable = unreadable + 1
                    return
                end
                for name in iter, dir_obj do
                    if name ~= "." and name ~= ".." and name:sub(1, 1) ~= "." then
                        local path = canonical == "/" and ("/" .. name) or (canonical .. "/" .. name)
                        local attr = lfs.attributes(path)
                        if attr and attr.mode == "directory" then
                            local resolved_dir = ffiUtil.realpath(path)
                            if not resolved_dir or not excluded_dirs[resolved_dir] then
                                visit(path)
                            end
                        elseif attr and attr.mode == "file" and DocumentRegistry:hasProvider(path) then
                            local resolved_path = ffiUtil.realpath(path) or path
                            local local_book, has_error = getLocalBookMetadata(resolved_path)
                            if has_error then metadata_failed = metadata_failed + 1 end
                            table.insert(candidates, local_book)
                        end
                    end
                end
            end
            visit(root)
            table.sort(candidates, function(a, b) return a.path < b.path end)
            return candidates, unreadable, metadata_failed
        end, info)

    UIManager:close(info)
    if not completed then return end
    if not local_books or #local_books == 0 then
        UIManager:show(InfoMessage:new{ text = _("No supported books found in that folder."), timeout = 5 })
        return
    end
    local attached_paths = {}
    for _, path in pairs(self.settings:readSetting("attachments") or {}) do
        if type(path) == "string" then
            attached_paths[ffiUtil.realpath(path) or path] = true
        end
    end
    local unique_local_books = {}
    local seen_paths = {}
    for _, local_book in ipairs(local_books) do
        if not attached_paths[local_book.path] and not seen_paths[local_book.path] then
            seen_paths[local_book.path] = true
            table.insert(unique_local_books, local_book)
        end
    end
    if #unique_local_books == 0 then
        UIManager:show(InfoMessage:new{ text = _("All supported books in that folder are already attached."), timeout = 5 })
        return
    end
    self:showSmartMatchMenu(books, unique_local_books, unreadable_dirs or 0, metadata_errors or 0)
end

function Hardcover:chooseFolderForMatching(books)
    local candidates = {
        G_reader_settings:readSetting("home_dir"),
        G_reader_settings:readSetting("lastdir"),
        Device.home_dir,
        DataStorage:getDataDir(),
        "/",
    }
    local path
    for _, candidate in ipairs(candidates) do
        path = readableDirectory(candidate)
        if path then break end
    end
    if not path then
        UIManager:show(InfoMessage:new{
            text = _("No readable folder found. Set a readable File Manager home folder and try again."),
            timeout = 5,
        })
        return
    end

    local chooser = PathChooser:new{
        title = _("Choose a folder to search recursively"),
        path = path,
        select_directory = true,
        select_file = false,
        onConfirm = function(folder)
            self:scanLocalFolderForMatches(folder, books)
        end,
    }
    UIManager:show(chooser)
end

function Hardcover:findLocalMatches()
    NetworkMgr:goOnlineToRun(function()
        local books, err = self:fetchUnattachedBooks()
        if not books then
            UIManager:show(InfoMessage:new{ text = err, timeout = 5 })
            return
        end
        if #books == 0 then
            UIManager:show(InfoMessage:new{ text = _("All Hardcover list and series books have local attachments."), timeout = 5 })
            return
        end
        self:chooseFolderForMatching(books)
    end)
end

function Hardcover:applyReadingProgressUpdates(updates, unchanged, skipped)
    if #updates == 0 then
        local summary = T(_("No progress changes applied; %1 unchanged; %2 skipped."),
            unchanged, skipped)
        self:recordSyncStatus("progress", summary, skipped > 0)
        UIManager:show(InfoMessage:new{ text = summary, timeout = 5 })
        return
    end

    local remote_updates, local_updates = {}, {}
    for _, update in ipairs(updates) do
        if update.direction == "to_hardcover" then
            table.insert(remote_updates, update)
        elseif update.direction == "to_local" then
            table.insert(local_updates, update)
        end
    end

    local remote_updated, local_updated = 0, 0
    local failed = skipped
    for batch_start = 1, #remote_updates, 20 do
        local mutations, batch_end = {}, math.min(batch_start + 19, #remote_updates)
        for index = batch_start, batch_end do
            local update = remote_updates[index]
            local pages = math.floor(update.local_percent * update.total_pages + 0.5)
            table.insert(mutations,
                ("sync_%d: update_user_book_read(id: %d, object: {progress_pages: %d}) { id }")
                    :format(index - batch_start + 1, update.id, pages))
        end
        local result = self:query("mutation {\n" .. table.concat(mutations, "\n") .. "\n}")
        if not result then
            failed = failed + batch_end - batch_start + 1
            for index = batch_start, batch_end do
                self:recordDiagnostic("Progress: " .. remote_updates[index].title,
                    self.last_query_error or _("Hardcover did not confirm this update."),
                    { type = "progress" })
            end
        else
            for index = batch_start, batch_end do
                if result["sync_" .. (index - batch_start + 1)] then
                    remote_updated = remote_updated + 1
                else
                    failed = failed + 1
                    self:recordDiagnostic("Progress: " .. remote_updates[index].title,
                        _("Hardcover did not confirm this update."),
                        { type = "progress" })
                end
            end
        end
    end

    local BookList = require("ui/widget/booklist")
    for _, update in ipairs(local_updates) do
        local ok, err = pcall(function()
            if lfs.attributes(update.path, "mode") ~= "file" then
                error(_("Local file is missing."))
            end
            local ReaderUI = require("apps/reader/readerui")
            local reader = ReaderUI.instance
            local current_file = reader and reader.document and reader.document.file
            if current_file and ffiUtil.realpath(current_file) == ffiUtil.realpath(update.path) then
                local Event = require("ui/event")
                reader:handleEvent(Event:new("GotoPercent", update.remote_percent * 100))
            else
                local settings = DocSettings:open(update.path)
                settings:saveSetting("percent_finished", update.remote_percent)
                settings:saveSetting("last_percent", update.remote_percent)
                local local_pages = tonumber(update.local_pages)
                if local_pages and local_pages > 0 then
                    settings:saveSetting("last_page",
                        math.max(1, math.min(local_pages,
                            math.floor(update.remote_percent * local_pages + 0.5))))
                end
                settings:delSetting("last_xpointer")
                settings:flush()
            end
            BookList.setBookInfoCacheProperty(update.path, "percent_finished", update.remote_percent)
        end)
        if ok then
            local_updated = local_updated + 1
        else
            failed = failed + 1
            self:recordDiagnostic("Progress to KOReader: " .. update.title, err, {
                type = "progress",
            })
        end
    end

    local summary = T(_("%1 sent to Hardcover; %2 applied to KOReader; %3 unchanged; %4 failed or skipped."),
        remote_updated, local_updated, unchanged, failed)
    self:recordSyncStatus("progress", summary, failed > 0)
    UIManager:show(InfoMessage:new{ text = summary, timeout = 5 })
end

function Hardcover:showReadingProgressPreview(updates, unchanged, skipped)
    local items = {{
        text = _("Apply selected progress changes (0)"),
        action = "sync",
    }}
    local direction_labels = {
        skip = _("No change"),
        to_hardcover = _("KOReader -> Hardcover"),
        to_local = _("Hardcover -> KOReader"),
    }
    local function updateHeader()
        local to_hardcover, to_local = 0, 0
        for _, update in ipairs(updates) do
            if update.direction == "to_hardcover" then
                to_hardcover = to_hardcover + 1
            elseif update.direction == "to_local" then
                to_local = to_local + 1
            end
        end
        items[1].text = T(_("Apply selected changes (%1 to Hardcover, %2 to KOReader)"),
            to_hardcover, to_local)
    end
    for _, update in ipairs(updates) do
        update.direction = "skip"
        local local_percent = update.local_percent
            and math.floor(update.local_percent * 100 + 0.5) or nil
        local remote_percent = math.floor(update.remote_percent * 100 + 0.5)
        table.insert(items, {
            text = T(_("%1: KOReader %2%%; Hardcover %3%%"),
                update.title, local_percent and tostring(local_percent) or _("unknown"),
                remote_percent),
            mandatory = direction_labels.skip,
            update = update,
        })
    end

    local menu
    menu = Menu:new{
        title = T(_("Review progress updates (%1 unchanged; %2 skipped)"), unchanged, skipped),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            if item.action == "sync" then
                local selected = {}
                for _, update in ipairs(updates) do
                    if update.direction ~= "skip" then table.insert(selected, update) end
                end
                if #selected == 0 then
                    UIManager:show(InfoMessage:new{ text = _("No progress changes selected."), timeout = 3 })
                    return
                end
                local to_hardcover, to_local = 0, 0
                for _, update in ipairs(selected) do
                    if update.direction == "to_hardcover" then
                        to_hardcover = to_hardcover + 1
                    else
                        to_local = to_local + 1
                    end
                end
                UIManager:show(ConfirmBox:new{
                    text = T(_("Apply %1 changes to Hardcover and %2 to KOReader? Selected changes can move progress in either direction. KOReader resume position is estimated by percentage."),
                        to_hardcover, to_local),
                    ok_text = _("Apply"),
                    ok_callback = function()
                        self:applyReadingProgressUpdates(selected, unchanged, skipped)
                    end,
                })
            elseif item.update then
                local directions = item.update.local_percent ~= nil
                    and { "skip", "to_hardcover", "to_local" } or { "skip", "to_local" }
                local current = 1
                for index, direction in ipairs(directions) do
                    if item.update.direction == direction then current = index break end
                end
                item.update.direction = directions[current % #directions + 1]
                item.mandatory = direction_labels[item.update.direction]
                updateHeader()
                menu:switchItemTable(nil, items)
            end
        end,
    }
    UIManager:show(menu)
end

--- Compare local progress with existing Hardcover read records for reviewed two-way sync.
function Hardcover:syncReadingProgress()
    NetworkMgr:goOnlineToRun(function()
        local attachments = self.settings:readSetting("attachments") or {}
        local progress_by_id = {}
        local ids = {}
        local skipped = 0
        for book_id, path in pairs(attachments) do
            local numeric_id = tonumber(book_id)
            local percent, pages, local_pages = localReadingProgress(path)
            if numeric_id and type(path) == "string" and lfs.attributes(path, "mode") == "file" then
                progress_by_id[tostring(numeric_id)] = {
                    percent = percent,
                    pages = pages,
                    local_pages = local_pages,
                    path = path,
                }
                table.insert(ids, numeric_id)
            else
                skipped = skipped + 1
            end
        end
        table.sort(ids)

        if #ids == 0 then
            self:applyReadingProgressUpdates({}, 0, skipped)
            return
        end

        local ids_text = table.concat(ids, ", ")
        local data = self:query(([[
        query {
            me {
                user_books(where: {book_id: {_in: [%s]}}) {
                    book_id book { title }
                    user_book_reads(order_by: {id: desc}, limit: 1) {
                        id progress_pages edition { pages }
                    }
                }
            }
        }]]):format(ids_text))
        local me = data and data.me and data.me[1]
        if not me then
            local summary = self.last_query_error or _("Failed to fetch Hardcover reading records.")
            self:recordSyncStatus("progress", summary, true)
            self:recordDiagnostic("Progress sync", summary)
            return
        end

        local updates = {}
        local found = {}
        local unchanged = 0
        for _, user_book in ipairs(me.user_books or {}) do
            local book_id = tostring(user_book.book_id)
            local local_progress = progress_by_id[book_id]
            local read = user_book.user_book_reads and user_book.user_book_reads[1]
            if local_progress and not found[book_id] then
                found[book_id] = true
                if read then
                    local edition = read.edition
                    if type(edition) == "table" and edition[1] then
                        edition = edition[1]
                    end
                    local pages = tonumber(type(edition) == "table" and edition.pages)
                        or local_progress.pages
                    local remote_pages = tonumber(read.progress_pages) or 0
                    if pages and pages > 0 then
                        local remote_percent = math.max(0, math.min(1, remote_pages / pages))
                        local read_id = tonumber(read.id)
                        if local_progress.percent ~= nil
                                and math.abs(local_progress.percent - remote_percent) < 0.01 then
                            unchanged = unchanged + 1
                        elseif read_id then
                            table.insert(updates, {
                                id = read_id,
                                path = local_progress.path,
                                local_percent = local_progress.percent,
                                local_pages = local_progress.local_pages or pages,
                                remote_percent = remote_percent,
                                remote_pages = remote_pages,
                                total_pages = pages,
                                title = metadataText(user_book.book and user_book.book.title)
                                    or T(_("Hardcover book %1"), book_id),
                            })
                        else
                            skipped = skipped + 1
                        end
                    else
                        skipped = skipped + 1
                    end
                else
                    skipped = skipped + 1
                end
            end
        end

        for book_id in pairs(progress_by_id) do
            if not found[book_id] then skipped = skipped + 1 end
        end

        if #updates == 0 then
            self:applyReadingProgressUpdates({}, unchanged, skipped)
            return
        end
        table.sort(updates, function(a, b) return a.title:lower() < b.title:lower() end)
        self:showReadingProgressPreview(updates, unchanged, skipped)
    end)
end

-- List / series browsers -----------------------------------------------

function Hardcover:searchListsAndSeries()
    local dialog
    dialog = InputDialog:new{
        title = _("Search Hardcover lists and series"),
        input_type = "string",
        buttons = {{
            {
                text = _("Cancel"),
                callback = function() UIManager:close(dialog) end,
            },
            {
                text = _("Search"),
                callback = function()
                    local needle = (dialog:getInputText() or ""):lower()
                    needle = needle:gsub("^%s+", ""):gsub("%s+$", "")
                    UIManager:close(dialog)
                    if needle == "" then
                        UIManager:show(InfoMessage:new{ text = _("Enter a search term."), timeout = 3 })
                        return
                    end

                    NetworkMgr:goOnlineToRun(function()
                        local lists = self:fetchLists()
                        local series_list = self:fetchSeries()
                        if not lists or not series_list then return end

                        local items = {}
                        for _, list in ipairs(lists) do
                            local name = metadataText(list.name) or "?"
                            if name:lower():find(needle, 1, true) then
                                table.insert(items, {
                                    text = T(_("List: %1"), name),
                                    search_text = name,
                                    list = list,
                                })
                            end
                        end
                        for _, series in ipairs(series_list) do
                            local name = metadataText(series.name) or "?"
                            if name:lower():find(needle, 1, true) then
                                table.insert(items, {
                                    text = T(_("Series: %1"), name),
                                    search_text = name,
                                    series = series,
                                })
                            end
                        end

                        if #items == 0 then
                            UIManager:show(InfoMessage:new{ text = _("No matching lists or series."), timeout = 3 })
                            return
                        end
                        local menu = Menu:new{
                            title = T(_("Search results: %1"), needle),
                            item_table = items,
                            is_borderless = false,
                            is_popout = false,
                            onMenuSelect = function(self_menu, item)
                                NetworkMgr:goOnlineToRun(function()
                                    if item.list then
                                        local books = self:fetchListBooks(item.list)
                                        if books then self:showBooksMenu(books, item.list.name) end
                                    else
                                        local books = self:fetchSeriesBooks(item.series)
                                        if books then
                                            self:showBooksMenu(books, item.series.name, item.series.name)
                                        end
                                    end
                                end)
                            end,
                        }
                        setMenuSearch(menu, items, function(item) return item.search_text end)
                        UIManager:show(menu)
                    end)
                end,
            },
        }},
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function Hardcover:browseLists()
    NetworkMgr:goOnlineToRun(function()
        local lists = self:fetchLists()
        if not lists then return end
        if #lists == 0 then
            UIManager:show(InfoMessage:new{ text = _("No lists found."), timeout = 3 })
            return
        end
        local items = {}
        for _, list in ipairs(lists) do
            local name = metadataText(list.name) or "?"
            table.insert(items, {
                text = ("%s (%d)"):format(name, list.books_count or 0),
                search_text = name,
                list = list,
            })
        end
        local menu = Menu:new{
            title = _("Hardcover lists"),
            item_table = items,
            is_borderless = false,
            is_popout = false,
            onMenuSelect = function(self_menu, item)
                NetworkMgr:goOnlineToRun(function()
                    local books = self:fetchListBooks(item.list)
                    if books then self:showBooksMenu(books, item.list.name) end
                end)
            end,
        }
        setMenuSearch(menu, items, function(item) return item.search_text end)
        UIManager:show(menu)
    end)
end

function Hardcover:browseSeries()
    NetworkMgr:goOnlineToRun(function()
        local series_list = self:fetchSeries()
        if not series_list then return end
        if #series_list == 0 then
            UIManager:show(InfoMessage:new{ text = _("No series followed."), timeout = 3 })
            return
        end
        local items = {}
        for _, s in ipairs(series_list) do
            local name = metadataText(s.name) or "?"
            table.insert(items, {
                text = ("%s (%d)"):format(name, s.primary_books_count or s.books_count or 0),
                search_text = name,
                series = s,
            })
        end
        local menu = Menu:new{
            title = _("Hardcover series"),
            item_table = items,
            is_borderless = false,
            is_popout = false,
            onMenuSelect = function(self_menu, item)
                NetworkMgr:goOnlineToRun(function()
                    local books = self:fetchSeriesBooks(item.series)
                    if books then self:showBooksMenu(books, item.series.name, item.series.name) end
                end)
            end,
        }
        setMenuSearch(menu, items, function(item) return item.search_text end)
        UIManager:show(menu)
    end)
end

function Hardcover:fetchUnattachedBooks(include_book_ids)
    local included = {}
    for book_id, should_include in pairs(include_book_ids or {}) do
        if should_include then included[tostring(book_id)] = true end
    end
    local lists = self:fetchLists()
    local series_list = self:fetchSeries()
    if not lists or not series_list then
        local message = self.last_query_error or _("Could not load all Hardcover lists and series.")
        self:recordDiagnostic("Unattached-book scan", message)
        return nil, message
    end

    local books_by_id = {}
    local sources_by_id = {}
    local function collectBooks(books, source)
        for _, book in ipairs(books) do
            if book.id then
                local id = tostring(book.id)
                books_by_id[id] = books_by_id[id] or book
                sources_by_id[id] = sources_by_id[id] or {}
                sources_by_id[id][source] = true
            end
        end
    end

    for _, list in ipairs(lists) do
        local books = self:fetchListBooks(list)
        if not books then
            local message = T(_("Could not load books from list: %1"), metadataText(list.name) or "?")
            self:recordDiagnostic("List: " .. (metadataText(list.name) or "?"), message, {
                type = "list",
                id = list.id,
            })
            return nil, message
        end
        collectBooks(books, T(_("List: %1"), metadataText(list.name) or "?"))
    end
    for _, series in ipairs(series_list) do
        local books = self:fetchSeriesBooks(series)
        if not books then
            local message = T(_("Could not load books from series: %1"), metadataText(series.name) or "?")
            self:recordDiagnostic("Series: " .. (metadataText(series.name) or "?"), message, {
                type = "series",
                id = series.id,
            })
            return nil, message
        end
        collectBooks(books, T(_("Series: %1"), metadataText(series.name) or "?"))
    end

    local unattached = {}
    for id, book in pairs(books_by_id) do
        if not self:getAttachment(book.id) or included[id] then
            local sources = {}
            for source in pairs(sources_by_id[id]) do
                table.insert(sources, source)
            end
            table.sort(sources)
            book.hardcover_sources = sources
            table.insert(unattached, book)
        end
    end
    table.sort(unattached, function(a, b)
        local a_title = (metadataText(a.title) or "?"):lower()
        local b_title = (metadataText(b.title) or "?"):lower()
        if a_title == b_title then return tostring(a.id) < tostring(b.id) end
        return a_title < b_title
    end)
    return unattached
end

function Hardcover:findReplacementFiles(stale_attachments)
    local stale_ids = {}
    for book_id in pairs(stale_attachments) do stale_ids[tostring(book_id)] = true end
    NetworkMgr:goOnlineToRun(function()
        local books, err = self:fetchUnattachedBooks(stale_ids)
        if not books then
            UIManager:show(InfoMessage:new{ text = err, timeout = 5 })
            return
        end
        local stale_books = {}
        for _, book in ipairs(books) do
            if stale_ids[tostring(book.id)] then table.insert(stale_books, book) end
        end
        if #stale_books == 0 then
            UIManager:show(InfoMessage:new{
                text = _("Could not find these books in your current Hardcover lists or series."),
                timeout = 5,
            })
            return
        end
        self:chooseFolderForMatching(stale_books)
    end)
end

function Hardcover:browseUnattachedBooks()
    NetworkMgr:goOnlineToRun(function()
        local books, err = self:fetchUnattachedBooks()
        if not books then
            UIManager:show(InfoMessage:new{ text = err, timeout = 5 })
            return
        end
        if #books == 0 then
            UIManager:show(InfoMessage:new{ text = _("All Hardcover list and series books have local attachments."), timeout = 5 })
            return
        end
        self:showBooksMenu(books, _("Books still to attach"))
    end)
end

function Hardcover:chooseBookSortOrder()
    local current = self.settings:readSetting("book_sort_mode") or "hardcover"
    local options = {
        { mode = "hardcover", text = _("Hardcover order") },
        { mode = "title", text = _("Title, A to Z") },
        { mode = "attached", text = _("Attached books first") },
    }
    local items = {}
    for _, option in ipairs(options) do
        table.insert(items, {
            text = option.text,
            mandatory = option.mode == current and _("Current") or nil,
            mode = option.mode,
        })
    end
    local menu
    menu = Menu:new{
        title = _("Sort Hardcover books"),
        item_table = items,
        onMenuSelect = function(self_menu, item)
            self.settings:saveSetting("book_sort_mode", item.mode)
            self.settings:flush()
            UIManager:close(menu)
            UIManager:show(InfoMessage:new{
                text = _("Sort order saved. Reopen a list or series to apply it."),
                timeout = 3,
            })
        end,
    }
    UIManager:show(menu)
end

-- ------------------------------------------------------------------: menu --

function Hardcover:addToMainMenu(menu_items)
    menu_items.hardcover = {
        text = _("Hardcover"),
        sorting_hint = "more_tools",
        sub_item_table = {
            {
                text = _("Browse my lists"),
                callback = function() self:browseLists() end,
            },
            {
                text = _("Browse my series trackers"),
                callback = function() self:browseSeries() end,
            },
            {
                text = _("Books still to attach"),
                callback = function() self:browseUnattachedBooks() end,
            },
            {
                text = _("Suggest local matches"),
                callback = function() self:findLocalMatches() end,
            },
            {
                text = _("Search lists and series"),
                callback = function() self:searchListsAndSeries() end,
            },
            {
                text = _("Review reading progress sync"),
                callback = function() self:syncReadingProgress() end,
            },
            {
                text = _("Show sync status"),
                callback = function() self:showSyncStatus() end,
            },
            {
                text = _("Scan for stale attachment records"),
                callback = function() self:scanStaleRecords() end,
            },
            {
                text = _("Preview collection refresh"),
                callback = function() self:browseCollectionsForRefresh() end,
            },
            {
                text = _("Sort Hardcover books"),
                callback = function() self:chooseBookSortOrder() end,
            },
            {
                text = _("Sync lists to Collections"),
                callback = function() self:syncListsToCollections() end,
            },
            {
                text = _("Sync series trackers to Collections"),
                callback = function() self:syncSeriesToCollections() end,
            },
            {
                text = _("Set access token"),
                callback = function() self:promptForToken() end,
            },
        },
    }
end

return Hardcover
