rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - moved earlier and more specific"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 30 7E 6A 5B }  // Early test and jump
        $pattern1 = { 83 C9 5F 0D 74 12 45 FC }  // Conditional check before exit
        $pattern2 = { 3D 00 00 00 F8 7F 1C }  // Unique instruction sequence
    condition:
        any of them
}