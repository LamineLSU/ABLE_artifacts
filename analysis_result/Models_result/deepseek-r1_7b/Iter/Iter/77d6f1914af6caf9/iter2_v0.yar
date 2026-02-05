rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved (Test EAX, Conditional Compare)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 83 F8 01 74 ?? ?? ?? ?? ?? }
        $pattern2 = { 83 F8 5E 74 ?? ?? ?? ?? ?? }

    condition:
        any of them
}