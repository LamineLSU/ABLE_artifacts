rule ExitProcess_Call_Signature
{
    meta:
        description = "Detects the call to ExitProcess in a Windows process"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { FF 75 08 E8 C8 FF FF FF }  // push dword ptr [ebp+08h] followed by call to ___crtCorExitProcess
        $b = { FF 75 08 FF 15 64 10 41 00 }  // push dword ptr [ebp+08h] followed by call to ExitProcess
        $c = { 55 8B EC FF 75 08 }  // push ebp, mov ebp, esp, push dword ptr [ebp+08h]
    condition:
        all of them
}