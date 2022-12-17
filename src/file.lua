local File = {}

function File.new(output)
	local self = {}
	for name, value in pairs(File) do
		self[name] = value
	end
	self.output = assert(io.open(output, 'wb'))
	return self
end

function File:write(value)
	self.output:write(value)
end

function File:writeln(value)
    self:write(value .. '\n')
end

function File:byte(number)
    self:write(string.char(number))
end

setmetatable(File, {
	__call = File.new
})

return File