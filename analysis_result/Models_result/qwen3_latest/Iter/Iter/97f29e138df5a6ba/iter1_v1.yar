rule ExitProcess_Call_Chain
{
    meta:
        description = "Detects a call chain to ExitProcess with conditional logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $a = { E8 CD 3D 00 00 83 F8 01 74 20 }
        $b = { FF 75 08 E8 ?? ?? ?? ?? }
        $c = { 55 8B EC E8 CD 3D 00 00 }

    condition:
        all of ($a, $b, $c)
}