-- DNS based Internet Access Policy
-- Check Block List, Default: Allow
-- Block List indexed by length

-- Configuration
ipv4_redirect_host = "127.0.0.1"
block_list_file = "block.db"
exact_match_only = false

-- Load List File
function load_list_file(file)
	local list = {}
	
	for line in io.lines(file) do
		if string.len(line) > 0 and string.sub(line, 1, 1) ~= "#" then
			local k = string.len(line) + 1
			if list[k] == nil then
				list[k] = {}
			end
			table.insert(list[k], line .. ".")
		end
	end
	
	return list
end

block_list = load_list_file(block_list_file)

function check_iap_acl(acl_list, domain)
	local l = string.len(domain)
	
	-- Check Exact Match First
	if acl_list[l] ~= nil then
		for k,v in pairs(acl_list[l]) do
			if domain == v then
				return true
			end
		end
	end
	
	-- Check for Partial / Ending Match
	if exact_match_only = false then
		for len,list in pairs(acl_list) do
			if len < l then
				for k,v in pairs(list) do
					if string.sub(domain, -string.len(v)) == v then
						return true
					end
				end
			end
		end
	end
	
	return false
end

-- Resolver Function Override
function preresolve(requestorip, domain, qtype)
	if qtype == pdns.A then
		if check_iap_acl(block_list, domain) then
			-- Redirect on Block List Match
			return 0, { {qtype=pdns.A, content=ipv4_redirect_host} }
		else
			-- Continue (Default Policy)
			return -1, {}
		end
	end
	
	-- Continue if not an A record.
	return -1, {}
end