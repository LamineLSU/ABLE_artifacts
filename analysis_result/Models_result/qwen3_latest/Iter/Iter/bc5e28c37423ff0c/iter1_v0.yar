rule EvasionPatterns
{
    meta:
        description = "Detects evasion techniques involving calls to ExitProcess and other suspicious functions."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        // Pattern 1: Call to ExitProcess with surrounding instructions
        $a = { 83 C4 ?? 52 FF D0 5E }  // add esp, 14h; push edx; call eax; pop esi
        
        // Pattern 2: Call to 0041EB27 with surrounding instructions
        $b = { 50 E8 ?? ?? ?? ?? 8B 55 ?? }  // push eax; call; mov edx, [ebp+0Ch]
        
        // Pattern 3: LEA instruction and surrounding pushes
        $c = { 8D B0 ?? ?? ?? ?? 56 50 }  // lea esi, [eax+0CA0h]; push esi; push eax
        
    condition:
        any of ($a, $b, $c)
}