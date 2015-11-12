-- DNS based Internet Access Policy
-- Check Block List, Default: Allow
-- Block List indexed by length
-- With added debug/print and os.clock comparison

-- Configuration
ipv4_redirect_host = "127.0.0.1"
block_list_file = "block.db"
exact_match_only = false

-- Exact Table Length
function tablelength(T)
	local count = 0
	for _ in pairs(T) do count = count + 1 end
	return count
end

-- Load List File
function load_list_file(file)
	local list = {}
	
	for line in io.lines(file) do
		if string.len(line) > 0 and string.sub(line, 1, 1) ~= "#" then
			local k = string.len(line) + 1
			if list[k] == nil then
				list[k] = {}
				print(string.format("New Index Key: %i\n", k))
			end
			table.insert(list[k], line .. ".")
		end
	end
	
	return list
end

print("Loading List File\n")
local x = os.clock()
block_list = load_list_file(block_list_file)
print(string.format("List File Loaded: %.2f\n", os.clock() - x))
print(string.format("Index Size: %i\n", tablelength(block_list)))

function check_iap_acl(acl_list, domain)
	print ("Begin check_iap_acl()")
	local x = os.clock()
	local l = string.len(domain)
	
	-- Check Exact Match First
	if acl_list[l] ~= nil then
		for k,v in pairs(acl_list[l]) do
			if domain == v then
				print(string.format("Iteration stopped for match: %.2f\n", os.clock() - x))
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
						print(string.format("Iteration stopped for match: %.2f\n", os.clock() - x))
						return true
					end
				end
			end
		end
	end
	
	print(string.format("Iteration complete: %.2f\n", os.clock() - x))
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