rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved to target exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? ?? ?? ?? ?? }  // Based on first exit process
        $pattern1 = { E8 C8 F5 04 10 0F 6A 01 02 03 }   // Longer sequence from second exit process
        $pattern2 = { 85 C0 0F 84 8B 45 E8 C8 F5 04 ?? } // Combined instructions with wildcards

    condition:
        any of them
}