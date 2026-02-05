rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 C0 E8 A5 91 FE FF }  // xor eax, eax + call to 00402754h
        $pattern1 = { 8B 85 9C FD FF FF E8 D9 CE FF FF }  // mov eax, [ebp-264h] + call to 00403D98h
        $pattern2 = { 8D 95 88 FD FF FF E8 28 E2 FE FF }  // lea edx, [ebp-278h] + call to 00407854h

    condition:
        any of them
}