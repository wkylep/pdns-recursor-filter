-- DNS based Internet Access Policy
-- Check Block List, Default: Allow
-- With added debug/print and os.clock comparison

-- Configuration
ipv4_redirect_host = "127.0.0.1"
block_list_file = "block.db"

-- Load List File
function load_list_file(file)
	local list = {}
	
	for line in io.lines(file) do
		if string.len(line) > 0 and string.sub(line, 1, 1) ~= "#" then
			table.insert(list, line .. ".")
		end
	end
	
	return list
end

print("Loading List File\n")
local x = os.clock()
block_list = load_list_file(block_list_file)
print(string.format("List File Loaded: %.2f\n", os.clock() - x))

function check_iap_acl(acl_list, domain)
	print ("Iterating list")
	local x = os.clock()
	for k,v in pairs(acl_list) do
		if string.sub(domain, -string.len(v)) == v then
			print("Iteration stopped for match: %.2f\n", os.clock() - x))
			return true
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
			-- Continue (Default Policy)
			return -1, {}
		end
	end
	
	-- Continue if not an A record.
	return -1, {}
end