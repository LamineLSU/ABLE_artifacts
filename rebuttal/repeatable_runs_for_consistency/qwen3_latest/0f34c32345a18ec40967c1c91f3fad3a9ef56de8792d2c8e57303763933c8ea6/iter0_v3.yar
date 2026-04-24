rule BypassCheck1
{
    meta:
        description = "Bypasses the IN AL, DX instruction which may be used for hardware communication checks."
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 8B 06 DB 0E 56 E8 } // MOV EAX, [ESI] | IN AL, DX | PUSH ESI | CALL (offsets wildcards)
    condition:
        all_of(
            $a
        )
}