rule StackManipulationCall
{
    meta:
        description = "Detects stack manipulation followed by a function call"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { FF 75 08 E8 ?? ?? ?? ?? 59 }
    condition:
        $a
}