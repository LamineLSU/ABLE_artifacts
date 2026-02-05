rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass analysis from trace data"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5C C3 FF ?? ?? ?? ?? ?? }
        $pattern1 = { 8B 45 8B EC ?? ?? ?? ?? ?? }
        $pattern2 = { 56 56 F7 4D 5E 5E ?? }

    condition:
        any of them
}