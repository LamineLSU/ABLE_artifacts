rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 } // Around call to E825050000 followed by TEST EAX
        $pattern1 = { E8 C8 FF FF FF 74 1A }      // Call to E8C8FFFFFF with conditional jump
        $pattern2 = { 6A ?? ?? ?? ?? 8B 45 }   // Around push instruction and subsequent mov

    condition:
        any of them
}