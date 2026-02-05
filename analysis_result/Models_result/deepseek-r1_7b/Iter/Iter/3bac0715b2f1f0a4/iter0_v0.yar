rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B EC 45 5A 87 ?? ?? ?? ?? } 
        $pattern1 = { 8D 0A 5E 9F F3 A3 C3 ?? ?? ?? ?? }
        $pattern2 = { 8B CA 6A 00 5A CE 45 ?? ?? ?? ?? }

    condition:
        any of them
}