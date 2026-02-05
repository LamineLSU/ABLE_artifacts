rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8A 01 3C 22 75 ?? }  // mov al, [ecx] | cmp al, 22h | jne
        $pattern1 = { 41 8A 11 84 D2 74 11 }  // inc ecx | mov dl, [ecx] | test dl, dl | je
        $pattern2 = { 8D 41 01 80 FA 22 0F 45 C1 }  // lea eax, [ecx+1] | cmp dl, 22h | cmovne eax, ecx

    condition:
        any of them
}