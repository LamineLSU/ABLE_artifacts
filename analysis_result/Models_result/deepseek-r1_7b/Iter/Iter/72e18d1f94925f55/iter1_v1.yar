rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific test and jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 58 3F 4D 97 C7 6C ?? } // E8CD3D?? ??
        $pattern1 = { 5A 4F 3B 28 F8 4E ?? } // E8BF31?? ??
        $pattern2 = { 08 7E FE D9 A4 68 ?? } // Conditional check before exit
    condition:
        (match_string $pattern0) || (match_string $pattern1) || (match_string $pattern2)
}