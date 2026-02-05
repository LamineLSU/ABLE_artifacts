rule Bypass_Sample
{
    meta:
        description = "Evasion bypass via memory displacement calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 6A 53 E8 25 05 00 00 }
        $pattern2 = { D9 E1 F4 FF FF 00 CE 01 10 00 01 85 03 }

    condition:
        any of them
}