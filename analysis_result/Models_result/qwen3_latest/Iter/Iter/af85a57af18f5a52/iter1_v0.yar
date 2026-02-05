rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, JE to check logic
        $pattern1 = { E8 ?? ?? ?? ?? }            // Generic call to evasion routine
        $pattern2 = { FF 15 ?? ?? ?? ?? }         // Call to ExitProcess (API bypass)

    condition:
        any of them
}