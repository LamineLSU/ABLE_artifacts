rule Bypass_ConditionalJump
{
    meta:
        description = "Bypass conditional jump check"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 51 8B F8 55 8B EC 83 F8 01 74 20 } //push ecx, mov edi, edi, push ebp, mov ebp, esp, cmp eax, 01h, je 0A14EC76h
    condition:
        any of them
}