rule ExitSequence
{
    meta:
        description = "Sequence leading to process termination"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 8B 45 ?? 50 E8 ?? ?? ?? ?? }
    condition:
        $a
}