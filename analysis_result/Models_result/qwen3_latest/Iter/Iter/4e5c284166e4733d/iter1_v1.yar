rule Evasion_Termination_Check {
    meta:
        description = "Detects evasion logic and ExitProcess call in memory"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { E8 CD 3D 00 00 83 F8 01 74 20 }
        $b = { C1 E8 08 A8 01 75 10 }
        $c = { 90 E8 ?? ?? ?? ?? }
    condition:
        all of ($a, $b, $c)
}