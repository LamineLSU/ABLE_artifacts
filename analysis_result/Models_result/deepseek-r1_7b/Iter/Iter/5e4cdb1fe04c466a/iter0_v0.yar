rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5E 4D FF 2F F8 C9 FF E7 3C 5D 5E }
        $pattern1 = { 8B EC 56 6A 36 6A 00 51 8D 45 FC 18 55 0C 8B 55 02 FF D0 FF D0 }
        $pattern2 = { 8B 55 0C 8B 55 02 FF D0 FF D0 5E 5D 5E }

    condition:
        any of them
}