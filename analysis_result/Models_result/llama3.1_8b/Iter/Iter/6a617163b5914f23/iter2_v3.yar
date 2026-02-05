rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 85 C0 0F 84 ?? ?? ?? ?? } // Test EAX and jump
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // Conditional check before exit
        $pattern2 = { B8 02 00 00 00 FF D0 5A } // API call with evasion check

    condition:
        any of them
}