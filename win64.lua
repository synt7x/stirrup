local file = require("src/file")
local assembly = require("src/assembly")
local machine = require("src/machine")


if not debug.getinfo(3) then
    local args = arg
    local alignment = 512
    local options = {}
    local output = 'program.asm'

    if #args > 0 then
        for i, argument in ipairs(args) do
            if argument == '-f' then
                i = i + 1

                options['-f' .. args[i]] = true
            elseif argument:find('^-f') ~= nil then
                options[argument] = true
            elseif argument == '-o' then
                i = i + 1

                output = args[i]
            elseif argument == '-a' then
                i = i + 1

                alignment = args[i]
            end
        end

        local file = file.new(output)

        if options['-fasm'] then
            print('Assembling')
            assembly(file, options, alignment)
        else
            machine(file, options, alignment)
        end
    else
        print("Stirrup - x86 PE Executable File Generator")
        print("Target: Win64")
    end
end