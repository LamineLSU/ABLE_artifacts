rule ExitProcess_Call
{
    meta:
        description = "Detects the call to ExitProcess with surrounding setup instructions"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $a = { 8B 06 83 C4 14 50 FF D0 }  // mov eax, [esi]; add esp, 14h; push edx; call eax

    condition:
        $a
}