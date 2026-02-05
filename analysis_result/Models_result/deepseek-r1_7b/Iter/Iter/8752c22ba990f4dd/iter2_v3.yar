rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional checks before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? ?? 8B 45 FC } // Initial setup
        $pattern1 = { E8 C1 FF FF FF ?? FF 75 08 ?? ?? 59 ?? ?? 00 00 00 0D } // Conditional check after first call
        $pattern2 = { 83 F8 01 74 12 ?? 8B 4D F8 } // Another instruction sequence

    condition:
        any of them
}