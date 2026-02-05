rule Evasion_Bypass
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8A 5F FF ?? ?? ED 3C AD ED EA }
        $pattern1 = { E8 1B 26 02 00 CA EC EA DE EE }
        $pattern2 = { F7 C0 0F ?? ?? ?? ?? 5E AE EA CA BA }

    condition:
        any of them
}