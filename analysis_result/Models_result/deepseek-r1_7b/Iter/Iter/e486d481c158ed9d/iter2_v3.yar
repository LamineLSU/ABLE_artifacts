rule Bypass_Evasion {
    meta:
        description = "Bypass evasion by targeting different instruction sequences from the provided traces."
        cape_options = "bp0=$pattern0,action0=skip,bp1=$pattern1,action1=skip,bp2=$pattern2,action2=skip,count=0"
    
    strings:
        $pattern0 = { 55 8B EC FF 75 08 ?? }  // Targets after push ebp and before mov ebp, esp
        $pattern1 = { E8 C8 ?? FF 75 08 }   // Targets during the call with wildcard displacement
        $pattern2 = { 59 FF 75 08 ?? ?? }  // Targets after pop ecx with wildcard context
    
    condition:
        any_of them
}