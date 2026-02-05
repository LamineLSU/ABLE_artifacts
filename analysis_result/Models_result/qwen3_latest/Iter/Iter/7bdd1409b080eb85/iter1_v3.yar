rule Targeted_Evasion_Checks
{
    meta:
        description = "Detects code injection patterns with conditional checks"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI Analyst"
    
    strings:
        $a = { 68 1C 27 47 00 FF 15 ?? ?? ?? ?? } // First PUSH + CALL to GetModuleHandleA
        $b = { FF 15 ?? ?? ?? ?? 85 C0 74 16 }      // CALL + TEST EAX + JE
        $c = { 68 0C 27 47 00 50 FF 15 ?? ?? ?? ?? } // Second PUSH + PUSH EAX + CALL to GetProcAddress
    
    condition:
        all of ($a, $b, $c)
}