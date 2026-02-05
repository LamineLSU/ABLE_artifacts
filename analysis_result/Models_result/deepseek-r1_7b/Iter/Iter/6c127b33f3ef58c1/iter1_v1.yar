rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }  // Test EAX and jump based on result
        $pattern1 = { 64 A1 30 00 ?? 8B 45 FC }  // Potential conditional after API call arguments
        $pattern2 = { FF 15 A0 F1 42 ?? 8B 75 08 }  // Check EAX before exit decision

    condition:
        any of them
}