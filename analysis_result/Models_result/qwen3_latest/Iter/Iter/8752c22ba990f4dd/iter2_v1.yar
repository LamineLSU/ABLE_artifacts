rule SpecificInstructionPattern
{
    meta:
        description = "Matches a sequence of instructions from a disassembled binary."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { 55 8B EC FF 75 08 }  // First three instructions: push ebp, mov ebp, push [ebp+08]
        $b = { FF 75 08 E8 ?? ?? ?? ?? }  // Push [ebp+08] followed by call to a function (offsets are wildcarded)
        $c = { FF 75 03 FF 15 ?? ?? ?? ?? }  // Push [ebp+03] followed by call to another function (address is wildcarded)

    condition:
        all of them
}