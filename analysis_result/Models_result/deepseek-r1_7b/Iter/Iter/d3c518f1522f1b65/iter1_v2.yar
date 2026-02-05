rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - improved with specific sequences from sample traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? ?? }
        $pattern1 = { 33 F8 01 74 12 8B 4D F8 ?? ?? }
        $pattern2 = { 0A FA 61 B1 5A ?? }

    condition:
        any of them
}