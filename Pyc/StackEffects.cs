namespace Opcodex.Pyc;

public readonly record struct StackEffect(int Pops, int Pushes, int JumpPops, int JumpPushes);

public static class StackEffectModel
{
    readonly record struct CountRule(int Base, int Scale = 0, char Mode = 'l', int Mask = 0)
    {
        public int Evaluate(int arg) => Mode switch
        {
            'b' => Base + ((arg & Mask) != 0 ? 1 : 0),
            'p' => Base + BitCount(arg & Mask),
            'u' => Base + (arg & 0xFF) + (arg >> 8),
            _ => Base + Scale * arg,
        };

        static int BitCount(int value)
        {
            int count = 0;
            while (value != 0) { count += value & 1; value >>= 1; }
            return count;
        }
    }

    readonly record struct Rule(CountRule Pops, CountRule Pushes, CountRule? JumpPops = null, CountRule? JumpPushes = null)
    {
        public StackEffect Evaluate(int arg)
        {
            int pops = Pops.Evaluate(arg), pushes = Pushes.Evaluate(arg);
            return new StackEffect(pops, pushes, (JumpPops ?? Pops).Evaluate(arg), (JumpPushes ?? Pushes).Evaluate(arg));
        }
    }

    static CountRule C(int n) => new(n);
    static CountRule A(int n = 0, int scale = 1) => new(n, scale);
    static CountRule B(int n, int mask) => new(n, 0, 'b', mask);
    static CountRule PC(int n, int mask) => new(n, 0, 'p', mask);
    static CountRule UX(int n) => new(n, 0, 'u');
    static Rule E(int pops, int pushes) => new(C(pops), C(pushes));
    static Rule V(CountRule pops, CountRule pushes) => new(pops, pushes);
    static Rule J(int pops, int pushes, int jumpPops, int jumpPushes) =>
        new(C(pops), C(pushes), C(jumpPops), C(jumpPushes));

    static readonly Dictionary<int, Dictionary<string, Rule>> Models = BuildModels();

    public static bool TryGetEffect(int minor, string name, int arg, out StackEffect effect)
    {
        effect = default;
        if (arg < 0) arg = 0;
        if (!Models.TryGetValue(minor, out var model) ||
            !model.TryGetValue(name, out var rule))
            return false;
        if (name == "CALL_INTRINSIC_1" &&
            OpcodeTable.Intrinsic1Name(arg) == "INTRINSIC_IMPORT_STAR")
        {
            effect = new StackEffect(1, 0, 1, 0);
            return true;
        }
        effect = rule.Evaluate(arg);
        return true;
    }

    public static bool IsModeled(int minor) => Models.ContainsKey(minor);

    static Dictionary<int, Dictionary<string, Rule>> BuildModels()
    {
        var t312 = new Dictionary<string, Rule>(StringComparer.Ordinal);
        void Add(Dictionary<string, Rule> t, string names, int pops, int pushes)
        {
            Rule rule = E(pops, pushes);
            foreach (string name in names.Split(' ', StringSplitOptions.RemoveEmptyEntries)) t[name] = rule;
        }
        void Put(Dictionary<string, Rule> t, string name, Rule rule) => t[name] = rule;

        Add(t312, "CACHE RESERVED NOP EXTENDED_ARG RESUME", 0, 0);
        Add(t312, "POP_TOP INTERPRETER_EXIT", 1, 0);
        Add(t312, "PUSH_NULL", 0, 1);
        Put(t312, "END_FOR", E(2, 0)); Put(t312, "END_SEND", E(2, 1));
        Add(t312, "UNARY_NEGATIVE UNARY_NOT UNARY_INVERT", 1, 1);
        Add(t312, "BINARY_SUBSCR", 2, 1); Add(t312, "BINARY_SLICE", 3, 1); Add(t312, "STORE_SLICE", 4, 0); Add(t312, "BINARY_OP", 2, 1);
        Add(t312, "GET_LEN MATCH_MAPPING MATCH_SEQUENCE", 1, 2); Add(t312, "MATCH_KEYS", 2, 3); Add(t312, "MATCH_CLASS", 3, 1);
        Add(t312, "PUSH_EXC_INFO", 1, 2); Add(t312, "CHECK_EXC_MATCH CHECK_EG_MATCH", 2, 2);
        Add(t312, "WITH_EXCEPT_START", 0, 1);
        Add(t312, "GET_AITER", 1, 1); Add(t312, "GET_ANEXT BEFORE_ASYNC_WITH BEFORE_WITH", 1, 2);
        Add(t312, "END_ASYNC_FOR", 2, 0); Add(t312, "CLEANUP_THROW", 3, 2);
        Add(t312, "STORE_SUBSCR", 3, 0); Add(t312, "DELETE_SUBSCR", 2, 0);
        Add(t312, "GET_ITER GET_YIELD_FROM_ITER", 1, 1);
        Add(t312, "LOAD_BUILD_CLASS LOAD_ASSERTION_ERROR", 0, 1); Add(t312, "RETURN_GENERATOR", 0, 1);
        Add(t312, "RETURN_VALUE", 1, 0); Add(t312, "RETURN_CONST SETUP_ANNOTATIONS", 0, 0);
        Add(t312, "LOAD_LOCALS", 0, 1); Add(t312, "POP_EXCEPT STORE_NAME STORE_GLOBAL", 1, 0);
        Add(t312, "DELETE_NAME DELETE_GLOBAL DELETE_FAST DELETE_DEREF MAKE_CELL COPY_FREE_VARS", 0, 0);
        Put(t312, "UNPACK_SEQUENCE", V(C(1), A()));
        Put(t312, "UNPACK_EX", V(C(1), UX(1)));
        Put(t312, "FOR_ITER", J(1, 2, 1, 2));
        Add(t312, "STORE_ATTR", 2, 0); Add(t312, "DELETE_ATTR", 1, 0);
        Put(t312, "SWAP", V(A(), A())); Put(t312, "COPY", V(A(), A(1)));
        Add(t312, "LOAD_CONST LOAD_NAME LOAD_FAST LOAD_FAST_CHECK LOAD_FAST_AND_CLEAR LOAD_CLOSURE LOAD_DEREF", 0, 1);
        Put(t312, "LOAD_GLOBAL", V(C(0), B(1, 1)));
        Add(t312, "BUILD_TUPLE BUILD_LIST BUILD_SET BUILD_STRING BUILD_SLICE", 0, 1);
        foreach (string n in new[] { "BUILD_TUPLE", "BUILD_LIST", "BUILD_SET", "BUILD_STRING", "BUILD_SLICE" }) Put(t312, n, V(A(), C(1)));
        Put(t312, "BUILD_MAP", V(A(0, 2), C(1))); Put(t312, "BUILD_CONST_KEY_MAP", V(A(1), C(1)));
        Put(t312, "LOAD_ATTR", V(C(1), B(1, 1))); Put(t312, "LOAD_SUPER_ATTR", V(C(3), B(1, 1)));
        Add(t312, "COMPARE_OP IS_OP CONTAINS_OP", 2, 1); Add(t312, "IMPORT_NAME", 2, 1); Add(t312, "IMPORT_FROM", 1, 2);
        Add(t312, "JUMP_FORWARD JUMP_BACKWARD JUMP_BACKWARD_NO_INTERRUPT", 0, 0);
        Add(t312, "POP_JUMP_IF_FALSE POP_JUMP_IF_TRUE POP_JUMP_IF_NONE POP_JUMP_IF_NOT_NONE", 1, 0);
        Put(t312, "RERAISE", V(A(1), A()));
        Put(t312, "SEND", J(2, 2, 2, 2));
        Add(t312, "STORE_FAST", 1, 0);
        Put(t312, "RAISE_VARARGS", V(A(), C(0))); Add(t312, "GET_AWAITABLE", 1, 1);
        Put(t312, "MAKE_FUNCTION", V(PC(1, 0xF), C(1)));
        Add(t312, "STORE_DEREF", 1, 0);
        Put(t312, "CALL_FUNCTION_EX", V(B(3, 1), C(1)));
        Add(t312, "LIST_APPEND SET_ADD", 1, 0); Add(t312, "MAP_ADD", 2, 0);
        Add(t312, "LIST_EXTEND SET_UPDATE DICT_MERGE DICT_UPDATE", 1, 0);
        Put(t312, "YIELD_VALUE", E(1, 1)); Put(t312, "FORMAT_VALUE", V(B(1, 4), C(1)));
        Put(t312, "CALL", V(A(2), C(1))); Add(t312, "KW_NAMES", 0, 0);
        Add(t312, "CALL_INTRINSIC_1", 1, 1); Add(t312, "CALL_INTRINSIC_2", 2, 1);
        Add(t312, "LOAD_FROM_DICT_OR_GLOBALS LOAD_FROM_DICT_OR_DEREF", 1, 1);

        var t313 = new Dictionary<string, Rule>(t312, StringComparer.Ordinal);
        t313.Remove("FORMAT_VALUE"); t313.Remove("KW_NAMES");
        Add(t313, "LOAD_FAST_LOAD_FAST", 0, 2); Add(t313, "STORE_FAST_LOAD_FAST", 1, 1); Add(t313, "STORE_FAST_STORE_FAST", 2, 0);
        Add(t313, "TO_BOOL FORMAT_SIMPLE CONVERT_VALUE", 1, 1);
        Put(t313, "END_FOR", E(1, 0));
        Put(t313, "FORMAT_WITH_SPEC", E(2, 1)); Put(t313, "CALL_KW", V(A(3), C(1)));
        Put(t313, "MAKE_FUNCTION", E(1, 1)); Put(t313, "SET_FUNCTION_ATTRIBUTE", E(2, 1));
        Add(t313, "EXIT_INIT_CHECK", 1, 0); Add(t313, "ENTER_EXECUTOR", 0, 0);

        var t314 = new Dictionary<string, Rule>(t313, StringComparer.Ordinal);
        foreach (string n in new[] { "LOAD_ASSERTION_ERROR", "BEFORE_WITH", "BEFORE_ASYNC_WITH", "RETURN_CONST", "BUILD_CONST_KEY_MAP", "LOAD_CLOSURE" }) t314.Remove(n);
        Add(t314, "LOAD_FAST_BORROW LOAD_SMALL_INT LOAD_COMMON_CONSTANT", 0, 1);
        Add(t314, "LOAD_FAST_BORROW_LOAD_FAST_BORROW", 0, 2);
        Add(t314, "LOAD_SPECIAL", 1, 2); Add(t314, "NOT_TAKEN", 0, 0);
        Add(t314, "END_FOR POP_ITER", 1, 0);
        Put(t314, "GET_ITER", E(1, 1)); Put(t314, "FOR_ITER", J(1, 2, 1, 2));
        Put(t314, "BUILD_TEMPLATE", E(2, 1)); Put(t314, "BUILD_INTERPOLATION", V(B(2, 1), C(1)));
        Put(t314, "CALL_FUNCTION_EX", E(4, 1));

        var t311 = new Dictionary<string, Rule>(t312, StringComparer.Ordinal);
        foreach (string n in new[] { "END_FOR", "END_SEND", "BINARY_SLICE", "STORE_SLICE", "LOAD_SUPER_ATTR", "RETURN_CONST", "CLEANUP_THROW",
                     "CALL_INTRINSIC_1", "CALL_INTRINSIC_2", "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR", "LOAD_LOCALS",
                     "LOAD_FROM_DICT_OR_GLOBALS", "LOAD_FROM_DICT_OR_DEREF", "INTERPRETER_EXIT", "RESERVED" }) t311.Remove(n);
        Add(t311, "UNARY_POSITIVE PRECALL KW_NAMES", 0, 0);
        Put(t311, "CALL", V(A(2), C(1))); Put(t311, "LOAD_ATTR", E(1, 1)); Put(t311, "LOAD_METHOD", E(1, 2));
        Add(t311, "LOAD_CLASSDEREF", 0, 1); Put(t311, "FOR_ITER", J(1, 2, 1, 0)); Put(t311, "SEND", J(2, 2, 2, 1));
        Put(t311, "JUMP_IF_FALSE_OR_POP", J(1, 0, 0, 0)); Put(t311, "JUMP_IF_TRUE_OR_POP", J(1, 0, 0, 0));
        Add(t311, "POP_JUMP_FORWARD_IF_FALSE POP_JUMP_FORWARD_IF_TRUE POP_JUMP_BACKWARD_IF_FALSE POP_JUMP_BACKWARD_IF_TRUE", 1, 0);
        Add(t311, "POP_JUMP_FORWARD_IF_NONE POP_JUMP_FORWARD_IF_NOT_NONE POP_JUMP_BACKWARD_IF_NONE POP_JUMP_BACKWARD_IF_NOT_NONE", 1, 0);
        Add(t311, "LIST_TO_TUPLE ASYNC_GEN_WRAP", 1, 1); Add(t311, "PREP_RERAISE_STAR", 2, 1); Add(t311, "PRINT_EXPR IMPORT_STAR", 1, 0);
        Put(t311, "MAKE_FUNCTION", V(PC(1, 0xF), C(1))); Put(t311, "CALL_FUNCTION_EX", V(B(3, 1), C(1)));

        var t310 = new Dictionary<string, Rule>(StringComparer.Ordinal);
        Add(t310, "NOP EXTENDED_ARG POP_BLOCK SETUP_ANNOTATIONS", 0, 0);
        Add(t310, "POP_TOP PRINT_EXPR IMPORT_STAR GEN_START", 1, 0);
        Add(t310, "ROT_TWO", 2, 2); Add(t310, "ROT_THREE", 3, 3); Add(t310, "ROT_FOUR", 4, 4);
        Put(t310, "ROT_N", V(A(), A())); Put(t310, "DUP_TOP", E(1, 2)); Put(t310, "DUP_TOP_TWO", E(2, 4));
        Add(t310, "UNARY_POSITIVE UNARY_NEGATIVE UNARY_NOT UNARY_INVERT", 1, 1);
        Add(t310, "BINARY_MATRIX_MULTIPLY INPLACE_MATRIX_MULTIPLY BINARY_POWER BINARY_MULTIPLY BINARY_MODULO BINARY_ADD BINARY_SUBTRACT BINARY_SUBSCR BINARY_FLOOR_DIVIDE BINARY_TRUE_DIVIDE INPLACE_FLOOR_DIVIDE INPLACE_TRUE_DIVIDE INPLACE_ADD INPLACE_SUBTRACT INPLACE_MULTIPLY INPLACE_MODULO BINARY_LSHIFT BINARY_RSHIFT BINARY_AND BINARY_XOR BINARY_OR INPLACE_POWER INPLACE_LSHIFT INPLACE_RSHIFT INPLACE_AND INPLACE_XOR INPLACE_OR", 2, 1);
        Add(t310, "STORE_SUBSCR", 3, 0); Add(t310, "DELETE_SUBSCR", 2, 0);
        Add(t310, "GET_ITER GET_YIELD_FROM_ITER", 1, 1); Add(t310, "LOAD_BUILD_CLASS", 0, 1); Add(t310, "YIELD_FROM", 2, 1); Add(t310, "GET_AWAITABLE", 1, 1); Add(t310, "RETURN_VALUE", 1, 0);
        Add(t310, "YIELD_VALUE", 1, 1); Add(t310, "POP_BLOCK SETUP_ANNOTATIONS", 0, 0);
        Add(t310, "GET_AITER", 1, 1); Add(t310, "GET_ANEXT BEFORE_ASYNC_WITH", 1, 2);
        Add(t310, "STORE_NAME", 1, 0); Add(t310, "DELETE_NAME DELETE_GLOBAL DELETE_FAST", 0, 0);
        Put(t310, "UNPACK_SEQUENCE", V(C(1), A())); Put(t310, "UNPACK_EX", V(C(1), UX(1)));
        Put(t310, "FOR_ITER", J(1, 2, 1, 0)); Add(t310, "STORE_ATTR", 2, 0); Add(t310, "DELETE_ATTR", 1, 0);
        Add(t310, "STORE_GLOBAL STORE_FAST STORE_DEREF", 1, 0); Add(t310, "LOAD_CONST LOAD_NAME LOAD_FAST LOAD_GLOBAL", 0, 1);
        foreach (string n in new[] { "BUILD_TUPLE", "BUILD_LIST", "BUILD_SET", "BUILD_STRING", "BUILD_SLICE" }) Put(t310, n, V(A(), C(1)));
        Put(t310, "BUILD_MAP", V(A(0, 2), C(1))); Put(t310, "BUILD_CONST_KEY_MAP", V(A(1), C(1)));
        Add(t310, "LOAD_ATTR", 1, 1); Add(t310, "COMPARE_OP", 2, 1); Add(t310, "IMPORT_NAME", 2, 1); Add(t310, "IMPORT_FROM", 1, 2);
        Add(t310, "JUMP_FORWARD JUMP_ABSOLUTE", 0, 0); Put(t310, "JUMP_IF_FALSE_OR_POP", J(1, 0, 0, 0)); Put(t310, "JUMP_IF_TRUE_OR_POP", J(1, 0, 0, 0));
        Add(t310, "POP_JUMP_IF_FALSE POP_JUMP_IF_TRUE", 1, 0);
        Add(t310, "RAISE_VARARGS", 0, 0); Put(t310, "RAISE_VARARGS", V(A(), C(0)));
        Add(t310, "CALL_FUNCTION", 0, 0); Put(t310, "CALL_FUNCTION", V(A(1), C(1)));
        Put(t310, "CALL_FUNCTION_KW", V(A(2), C(1))); Put(t310, "CALL_FUNCTION_EX", V(B(2, 1), C(1)));
        Put(t310, "LOAD_METHOD", E(1, 2)); Put(t310, "CALL_METHOD", V(A(2), C(1)));
        Put(t310, "MAKE_FUNCTION", V(PC(2, 0xF), C(1))); Add(t310, "LOAD_CLOSURE LOAD_DEREF LOAD_CLASSDEREF", 0, 1);
        Add(t310, "DELETE_DEREF", 0, 0); Add(t310, "STORE_DEREF", 1, 0);
        Add(t310, "LIST_APPEND SET_ADD", 1, 0); Add(t310, "MAP_ADD", 2, 0);
        Add(t310, "LIST_EXTEND SET_UPDATE DICT_MERGE DICT_UPDATE", 1, 0); Put(t310, "FORMAT_VALUE", V(B(1, 4), C(1)));
        Add(t310, "LOAD_ASSERTION_ERROR", 0, 1); Add(t310, "LIST_TO_TUPLE IS_OP CONTAINS_OP", 1, 1);
        Put(t310, "IS_OP", E(2, 1)); Put(t310, "CONTAINS_OP", E(2, 1)); Add(t310, "JUMP_IF_NOT_EXC_MATCH", 2, 0);
        Put(t310, "SETUP_FINALLY", J(0, 0, 0, 6)); Put(t310, "SETUP_WITH", J(1, 2, 1, 7)); Put(t310, "SETUP_ASYNC_WITH", J(1, 1, 1, 6));
        Add(t310, "POP_EXCEPT RERAISE", 3, 0); Add(t310, "WITH_EXCEPT_START", 0, 1); Add(t310, "END_ASYNC_FOR", 7, 0);
        Add(t310, "BEGIN_FINALLY", 0, 6); Add(t310, "END_FINALLY", 6, 0); Add(t310, "CALL_FINALLY", 0, 1);
        Add(t310, "WITH_CLEANUP_START", 0, 1); Add(t310, "WITH_CLEANUP_FINISH", 1, 0);
        Add(t310, "SETUP_LOOP SETUP_EXCEPT", 0, 0);

        return new Dictionary<int, Dictionary<string, Rule>>
        {
            [8] = t310, [9] = t310, [10] = t310, [11] = t311,
            [12] = t312, [13] = t313, [14] = t314,
        };
    }
}
