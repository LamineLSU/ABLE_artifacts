rule Bypass_Evasion_ Analyst
{
    meta:
        description = "Targeting ExitProcess calls with bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { D4 5D 8B 55 E8 FF D0 }
        $pattern1 = { DA AE 9A 61 8B EC 8B 55 E8 74 0A 00 00 }
        $pattern2 = { 8B EC 8B 55 E8 5E FF D0 }

    condition:
        any of them
}