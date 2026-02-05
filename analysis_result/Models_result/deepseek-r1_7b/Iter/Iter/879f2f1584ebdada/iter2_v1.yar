rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF F8 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { FE FE F8 FF ?? ?? ?? ?? 33 C9 5B }
        $pattern2 = { 8B EC 55 8C ?? ?? ?? ?? FF 0D 6A }

    condition:
        any of them
}