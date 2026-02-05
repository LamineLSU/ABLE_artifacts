rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass using specific instruction sequences"
        cape_options = "bp0=E8C8FF75??,action0=skip,bp1=59FF75??,action1=skip,bp2=???C8FFFF,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF 75 ?? } // Bypass after the first call by skipping the near jump
        $pattern1 = { 59 FF 75 ?? }      // Skip a conditional jump to alter execution flow
        $pattern2 = {  }         // Bypass an unknown instruction sequence for evasion
    condition:
        any of them
}