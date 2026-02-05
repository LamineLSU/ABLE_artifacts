rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific API and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 E8 07 26 00 00 }
        $pattern1 = { 8B EC 5A 4D F8 03 C3 }
        $pattern2 = { FF 15 2C A1 FA 00 }
        
    condition:
        any of them
}