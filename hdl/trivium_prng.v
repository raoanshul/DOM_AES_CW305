// =============================================================================
// Trivium-based PRNG for DOM AES Masking
// =============================================================================
//
// Produces 64 pseudo-random bits per clock cycle by unrolling 64 iterations
// of the Trivium stream cipher in combinational logic.
//
// Trivium state: 288 bits in 3 coupled shift registers
//   Register A: s1  .. s93   (93 bits)  -> state[92:0]
//   Register B: s94 .. s177  (84 bits)  -> state[176:93]
//   Register C: s178.. s288  (111 bits) -> state[287:177]
//
// Initialization:
//   1. Load 80-bit key into s1..s80 and 80-bit IV into s94..s173
//   2. Set s286=s287=s288=1, all other bits = 0
//   3. Clock for 1152 cycles (4 x 288) with init_busy=1, discarding output
//   4. After init_busy falls, rng_out is valid
//
// Interface:
//   clk        - clock
//   rst        - synchronous reset (active high)
//   key        - 80-bit key (latched on rst)
//   iv         - 80-bit initialization vector (latched on rst)
//   en         - enable (advance state and produce output when high)
//   init_busy  - high during the 1152-cycle warm-up phase
//   rng_out    - 64-bit random output, valid when init_busy=0 and en=1
// =============================================================================

module trivium_prng #(
    parameter BITS_PER_CYCLE = 64   // Number of output bits per clock cycle
)(
    input  wire        clk,
    input  wire        rst,
    input  wire [79:0] key,
    input  wire [79:0] iv,
    input  wire        en,
    output wire        init_busy,
    output wire [BITS_PER_CYCLE-1:0] rng_out
);

    // =========================================================================
    // State registers (288 bits total)
    // =========================================================================
    // Mapping from Trivium spec (1-indexed) to Verilog (0-indexed):
    //   s_k  (spec)  =  state[k-1]  (Verilog)
    //   Register A: state[92:0]    = s1..s93
    //   Register B: state[176:93]  = s94..s177
    //   Register C: state[287:177] = s178..s288

    reg [92:0]   a;    // Register A
    reg [83:0]   b;    // Register B
    reg [110:0]  c;    // Register C

    // =========================================================================
    // Initialization counter
    // =========================================================================
    // Trivium requires 4*288 = 1152 warm-up clocks before output is usable.

    reg [10:0] init_counter;  // counts 0..1152
    assign init_busy = (init_counter < 11'd1152);

    // =========================================================================
    // 64-iteration combinational unrolling
    // =========================================================================
    // We compute 64 Trivium iterations in pure combinational logic.
    // Each iteration k uses the state from iteration k-1.
    // The output bits and final state are all wires.

    // Intermediate state arrays: [0] = current state, [k] = state after k iterations
    wire [92:0]  a_chain [0:BITS_PER_CYCLE];
    wire [83:0]  b_chain [0:BITS_PER_CYCLE];
    wire [110:0] c_chain [0:BITS_PER_CYCLE];

    // Seed the chain with current register state
    assign a_chain[0] = a;
    assign b_chain[0] = b;
    assign c_chain[0] = c;

    // Output bit array
    wire [BITS_PER_CYCLE-1:0] z_bits;

    genvar i;
    generate
        for (i = 0; i < BITS_PER_CYCLE; i = i + 1) begin : trivium_iter

            // Shorthand wires for the current iteration's state
            wire [92:0]  ai = a_chain[i];
            wire [83:0]  bi = b_chain[i];
            wire [110:0] ci = c_chain[i];

            // ---------------------------------------------------------------
            // Trivium tap indices (0-indexed within each register):
            //
            // Register A (93 bits, s1..s93 = a[92:0]):
            //   s66  = a[65]     (output tap)
            //   s69  = a[68]     (feedback from C)
            //   s91  = a[90]     (AND input)
            //   s92  = a[91]     (AND input)
            //   s93  = a[92]     (output tap / end of register)
            //
            // Register B (84 bits, s94..s177 = b[83:0]):
            //   s162 = b[68]     (output tap)
            //   s171 = b[77]     (feedback from A)
            //   s175 = b[81]     (AND input)
            //   s176 = b[82]     (AND input)
            //   s177 = b[83]     (output tap / end of register)
            //
            // Register C (111 bits, s178..s288 = c[110:0]):
            //   s243 = c[65]     (output tap)
            //   s264 = c[86]     (feedback from B)
            //   s286 = c[108]    (AND input)
            //   s287 = c[109]    (AND input)
            //   s288 = c[110]    (output tap / end of register)
            // ---------------------------------------------------------------

            // Output bit: XOR of the three "end" taps and "mid" taps
            wire t1 = ai[65] ^ ai[92];
            wire t2 = bi[68] ^ bi[83];
            wire t3 = ci[65] ^ ci[110];

            assign z_bits[i] = t1 ^ t2 ^ t3;

            // Feedback values (includes the AND nonlinearity)
            wire fb_a = t1 ^ (ai[90] & ai[91]) ^ bi[77];   // feeds into B
            wire fb_b = t2 ^ (bi[81] & bi[82]) ^ ci[86];    // feeds into C
            wire fb_c = t3 ^ (ci[108] & ci[109]) ^ ai[68];  // feeds into A

            // Shift each register right by 1, insert feedback at position [0]
            // New state: a_new[0] = fb_c, a_new[k] = a_old[k-1] for k=1..92
            assign a_chain[i+1] = {ai[91:0], fb_c};
            assign b_chain[i+1] = {bi[82:0], fb_a};
            assign c_chain[i+1] = {ci[109:0], fb_b};

        end
    endgenerate

    // Output assignment
    assign rng_out = z_bits;

    // =========================================================================
    // State update (sequential logic)
    // =========================================================================

    always @(posedge clk) begin
        if (rst) begin
            // -----------------------------------------------------------------
            // Initialization: load key and IV into the state
            // -----------------------------------------------------------------
            // Register A: s1..s80 = key[0..79], s81..s93 = 0
            //   a[79:0] = key,  a[92:80] = 0
            a <= {13'b0, key};

            // Register B: s94..s173 = iv[0..79], s174..s177 = 0
            //   b[79:0] = iv,  b[83:80] = 0
            b <= {4'b0, iv};

            // Register C: s286..s288 = 1, rest = 0
            //   c[110:108] = 3'b111,  c[107:0] = 0
            c <= {3'b111, 108'b0};

            init_counter <= 11'd0;

        end else if (en) begin
            // Advance state by BITS_PER_CYCLE iterations
            a <= a_chain[BITS_PER_CYCLE];
            b <= b_chain[BITS_PER_CYCLE];
            c <= c_chain[BITS_PER_CYCLE];

            // Increment init counter (saturates at 1152)
            if (init_counter < 11'd1152) begin
                init_counter <= init_counter + 11'd1;
            end
        end
    end

endmodule