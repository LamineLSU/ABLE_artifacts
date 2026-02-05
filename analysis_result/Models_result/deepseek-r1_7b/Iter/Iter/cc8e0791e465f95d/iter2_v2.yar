rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F8 E8 ?? ?? EB ?? CA ?? AD EA 08 }
        $pattern1 = { FF D2 F8 C3 04 8B 4D 08 EB F8 C2 08 }
        $pattern2 = { 6A 5A 8B CE E8 ?? ?? EB ?? CA ?? AD ED 14 }

    condition:
        any of them
}