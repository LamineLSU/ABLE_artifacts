rule ProcessTermination
{
    meta:
        description = "Detects process termination logic using CRT and Windows Exit functions"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p2+0,action2=skip,count=0"
    strings:
        $p0 = { FF 75 08 E8 C8 FF FF FF 59 }
        $p1 = { FF 75 08 FF 15 AC B0 41 00 59 }
        $p2 = { 59 FF 75 08 E8 C8 FF FF }
    condition:
        any of ($p0, $p1, $p2)
}