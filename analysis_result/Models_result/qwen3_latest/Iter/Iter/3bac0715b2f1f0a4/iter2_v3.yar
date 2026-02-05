rule Sample_Bypass
{
    meta:
        description = "Detects code flow patterns from the sample"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 8B 88 18 0A 00 00 }  // mov ecx, [eax+0A18h]
        $b = { 8D B0 A0 0C 00 00 }  // lea esi, [eax+CA0h]
        $c = { 8B 55 0C 8B 06 83 C4 14 52 FF D0 }  // Sequence leading to call eax
    
    condition:
        all of them
}