rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL+TEST+JE sequence
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }                  // TEST+JE sequence
        $pattern2 = { 8B 85 ?? ?? ?? ?? 03 C3 03 C1 }            // Arithmetic check sequence

    condition:
        any of them
}