/*
AES DOM Wrapper - Interface between CW305 and Domain-Oriented Masking AES

This module wraps the aes_top.vhdl (DOM protected AES) and provides:
1. Parallel-to-byte-serial conversion for plaintext/key
2. Share splitting (masking) for side-channel protection
3. Randomness generation (LFSR-based PRNG)
4. Ciphertext collection and share recombination
5. CW305-compatible control interface

TIMING NOTE on DonexSO:
  In the perfectly interleaved variant, DonexSO = State1xS AND LastRoundxS.
  LastRoundxS is HIGH during BOTH the preliminary round (after RCON reset) and
  round 10 (actual last round). So DonexSO fires TWICE per encryption:
    1st pulse: start of preliminary round  -> We IGNORE this pulse and do NOT start collecting Ciphertext yet.
    2nd pulse: start of round 10           -> Here we START collecting Ciphertext bytes on subsequent cycles.
*/

`timescale 1ns / 1ps
`default_nettype none

module aes_dom_wrapper #(
    parameter pPT_WIDTH  = 128,
    parameter pKEY_WIDTH = 128,
    parameter pCT_WIDTH  = 128,
    // DOM protection order: N=1 means 2 shares (first-order protection)
    parameter N = 1
)(
    // Clock and Reset
    input  wire                     clk,
    input  wire                     rst,
    
    // =========================================================================
    // Parallel Interface (compatible with existing CW305 register module)
    // =========================================================================
    
    // Parallel inputs (directly from registers)
    input  wire [pPT_WIDTH-1:0]     pt_parallel,    // Full 128-bit plaintext
    input  wire [pKEY_WIDTH-1:0]    key_parallel,   // Full 128-bit key
    
    // Parallel output
    output wire [pCT_WIDTH-1:0]     ct_parallel,    // Full 128-bit ciphertext
    
    // Control signals
    input  wire                     load,           // Start encryption (pulse)
    output wire                     busy,           // Encryption in progress
    output wire                     done,           // Single-cycle pulse when CT is ready
    
    // Optional: PRNG seed (can be loaded via register)
    input  wire [63:0]              prng_seed
);
    // =========================================================================
    // Local Parameters
    // =========================================================================
    
    localparam NUM_SHARES = N + 1;
    
    localparam ZMUL_WIDTH = (N*(N+1)/2) * 4;  // 4 bits for N=1
    localparam ZINV_WIDTH = (N*(N+1)/2) * 2;  // 2 bits for N=1
    localparam BMUL_WIDTH = (N+1) * 4;        // 8 bits for N=1
    localparam BINV_WIDTH = (N+1) * 2;        // 4 bits for N=1
    
    
    // =========================================================================
    // Internal Signals
    // =========================================================================
    
    // Latched parallel data
    reg [127:0] pt_latched;
    reg [127:0] key_latched;
    reg [127:0] ct_collected;
    
    // Byte selection counter
    reg [7:0] cycle_counter;
    reg       running;
    
    wire [3:0] byte_index = cycle_counter[3:0];
    
    // DOM core interface signals
    reg        dom_start_r;
    wire       dom_done;
    
    // The DOM LFSR doesn't return to IDLE after encryption completes.
    // Reset Signal needed for the Encryption to return to IDLE state
    reg        dom_soft_rst;
    reg [1:0]  start_seq;           // 2-bit sequencer: 0=idle, 1=reset, 2=start, 3=running
    
    // CT collection state
    reg        first_done_seen;     // tracks unwanted 1st dom_done
    reg        collecting_ct;
    reg [4:0]  ct_byte_count;
    reg        done_r;
    
    // =========================================================================
    // Byte Selection
    // =========================================================================
    //
    // MSB-first: the CW305 Python API reverses the byte array before writing,
    // so AES byte 0 ends up at reg[127:120]. The DOM core expects AES byte 0
    // first, so we read from the MSB downward.
    
    wire [7:0] current_pt_byte;
    wire [7:0] current_key_byte;
    
    assign current_pt_byte  = pt_latched[127 - byte_index*8 -: 8];
    assign current_key_byte = key_latched[127 - byte_index*8 -: 8];
    
    
    // =========================================================================
    // Share Splitting
    // =========================================================================
    
    wire [7:0] pt_mask;
    wire [7:0] key_mask;
    
    wire [7:0] dom_pt_share  [0:N];
    wire [7:0] dom_key_share [0:N];
    wire [7:0] dom_ct_share  [0:N];
    
    assign dom_pt_share[0]  = current_pt_byte ^ pt_mask;
    assign dom_pt_share[1]  = pt_mask;
    assign dom_key_share[0] = current_key_byte ^ key_mask;
    assign dom_key_share[1] = key_mask;
    
    // =========================================================================
    // PRNG (LFSR-based)
    // =========================================================================
    
    wire [ZMUL_WIDTH-1:0] zmul1, zmul2, zmul3;
    wire [ZINV_WIDTH-1:0] zinv1, zinv2, zinv3;
    wire [BMUL_WIDTH-1:0] bmul1;
    wire [BINV_WIDTH-1:0] binv1, binv2, binv3;
    
    reg [63:0] prng_state;  
    
    wire lfsr_bit = prng_state[63] ^ prng_state[62] ^ prng_state[60] ^ prng_state[59];
    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            prng_state <= (prng_seed != 64'b0) ? prng_seed : 64'hDEADBEEFCAFEBABE;
        end else if (running) begin
            prng_state <= {prng_state[62:0], lfsr_bit};
        end
    end
    
    assign pt_mask  = prng_state[7:0];
    assign key_mask = prng_state[15:8];
    
    assign zmul1 = prng_state[19:16];
    assign zmul2 = prng_state[23:20];
    assign zmul3 = prng_state[27:24];
    
    assign zinv1 = prng_state[29:28];
    assign zinv2 = prng_state[31:30];
    assign zinv3 = prng_state[33:32];
    
    assign bmul1 = prng_state[41:34];
    
    assign binv1 = prng_state[45:42];
    assign binv2 = prng_state[49:46];
    assign binv3 = prng_state[53:50];

    // =========================================================================
    // Latch Inputs
    // =========================================================================
    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            pt_latched  <= 128'b0;
            key_latched <= 128'b0;
        end else if (load && !running) begin
            pt_latched  <= pt_parallel;
            key_latched <= key_parallel;
        end
    end
    
    // =========================================================================
    // Main FSM
    // =========================================================================
    //
    // Sequence:
    //   1. load pulse               -> running=1, dom_start_r pulsed, counter=0
    //   2. Start cycle (dom_start_r=1):
    //      - DOM core sees StartxSI=1, RCON resets asynchronously
    //      - Counter does NOT advance (byte 0 held for one extra cycle)
    //   3. DOM FSM enters State1    -> reads PTxDI/KxDI byte 0
    //      - Counter starts advancing: byte 1, 2, ..., 15
    //   4. Preliminary round done   -> dom_done fires (1st pulse) -> IGNORED
    //   5. Rounds 1-9 execute       -> ~180 cycles, dom_done stays low
    //   6. Round 10 starts          -> dom_done fires (2nd pulse) -> CT collection
    //   7. Collect 16 CT bytes      -> done_r pulsed, running=0
    
    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            running         <= 1'b0;
            cycle_counter   <= 8'd0;
            dom_start_r     <= 1'b0;
            dom_soft_rst    <= 1'b0;
            start_seq       <= 2'd0;
            first_done_seen <= 1'b0;
            collecting_ct   <= 1'b0;
            ct_byte_count   <= 5'd0;
            done_r          <= 1'b0;

        end else begin
            dom_start_r  <= 1'b0;  // default: no start pulse
            dom_soft_rst <= 1'b0;  // default: no reset pulse
            done_r       <= 1'b0;  // default: no done pulse

            // =====================================================================
            // Start sequencer: ensures DOM core LFSR is reset before Start pulse
            // =====================================================================
            // The DOM LFSR does NOT return to IDLE (STATE_0) after encryption.
            // If we pulse Start when LFSR is mid-cycle, the FSM corrupts into an
            // invalid state. Fix: pulse soft reset first, then Start.
            //
            // Sequence:
            //   start_seq=0 (idle): waiting for load
            //   start_seq=1 (reset): assert dom_soft_rst for 1 cycle
            //   start_seq=2 (start): assert dom_start_r for 1 cycle
            //   start_seq=3 (running): normal operation
            // =====================================================================
            
            case (start_seq)
                2'd0: begin  // IDLE - wait for load
                    if (load && !running) begin
                        running       <= 1'b1;
                        cycle_counter <= 8'd0;
                        dom_soft_rst  <= 1'b1;   // pulse reset to DOM core
                        start_seq     <= 2'd1;
                        first_done_seen <= 1'b0;
                        collecting_ct   <= 1'b0;
                        ct_byte_count   <= 5'd0;
                    end
                end
                
                2'd1: begin  // RESET phase - DOM core is being reset this cycle
                    // LFSR is now reset to STATE_0, safe to pulse Start
                    dom_start_r <= 1'b1;
                    start_seq   <= 2'd2;
                end
                
                2'd2: begin  
                    // LFSR transitions STATE_0 to STATE_1 at end of this cycle
                    start_seq <= 2'd3;
                end
                
                2'd3: begin  // RUNNING phase - normal encryption operation
                    // --- Byte counter ---
                    // Counter=0 @ STATE_1
                    // counter=1 with STATE_2
                    if (cycle_counter != 8'd15)
                        cycle_counter <= cycle_counter + 8'd1;

                    // --- Handle dom_done pulses ---
                    if (dom_done && !collecting_ct) begin
                        if (!first_done_seen) begin
                            first_done_seen <= 1'b1; // 1st DOM DONE pulse ignored
                        end else begin
                            collecting_ct <= 1'b1;
                            ct_byte_count <= 5'd0;
                        end
                    end

                    // --- CT collection ---
                    if (collecting_ct) begin
                        ct_byte_count <= ct_byte_count + 5'd1;

                        if (ct_byte_count == 5'd14) begin
                            running       <= 1'b0;
                            collecting_ct <= 1'b0;
                            done_r        <= 1'b1;
                            start_seq     <= 2'd0;  // back to idle for next encryption
                        end
                    end
                end
            endcase
        end
    end

// =========================================================================
    // Ciphertext Collection
    // =========================================================================

    wire [7:0] ct_byte_combined = dom_ct_share[0] ^ dom_ct_share[1];
    
    // The first valid CT byte appears on CxDO on the SAME cycle as the real
    // (2nd) dom_done pulse. Capture it immediately, then collecting_ct handles
    // the remaining 15 bytes on subsequent cycles.
    wire ct_capture = (dom_done && running && first_done_seen && !collecting_ct)
                    || collecting_ct;
    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            ct_collected <= 128'b0;
        end else if (load && !running) begin
            ct_collected <= 128'b0;
        end else if (ct_capture) begin
            ct_collected <= {ct_collected[119:0], ct_byte_combined};
        end
    end
    
    // =========================================================================
    // Outputs
    // =========================================================================
    
    assign ct_parallel = ct_collected;
    assign busy        = running;
    assign done        = done_r;
    
    // =========================================================================
    // DOM AES Core Instantiation
    // =========================================================================
    
    wire [NUM_SHARES*8-1:0] pt_shares_flat;
    wire [NUM_SHARES*8-1:0] key_shares_flat;
    wire [NUM_SHARES*8-1:0] ct_shares_flat;
    
    assign pt_shares_flat  = {dom_pt_share[1], dom_pt_share[0]};
    assign key_shares_flat = {dom_key_share[1], dom_key_share[0]};
    
    assign dom_ct_share[0] = ct_shares_flat[7:0];
    assign dom_ct_share[1] = ct_shares_flat[15:8];
    
    
    // Combine global reset with soft reset for DOM core
    // This ensures LFSR returns to STATE_0 before each new encryption
    wire dom_rst_n = ~rst & ~dom_soft_rst;
    
    aes_dom_verilog_wrapper #(
        .N(N)
    ) u_aes_dom (
        .clk_i       (clk),
        .rst_ni      (dom_rst_n),    // use combined reset
        
        .pt_shares_i (pt_shares_flat),
        .key_shares_i(key_shares_flat),
        .ct_shares_o (ct_shares_flat),
        
        .zmul1_i     (zmul1),
        .zmul2_i     (zmul2),
        .zmul3_i     (zmul3),
        .zinv1_i     (zinv1),
        .zinv2_i     (zinv2),
        .zinv3_i     (zinv3),
        
        .bmul1_i     (bmul1),
        .binv1_i     (binv1),
        .binv2_i     (binv2),
        .binv3_i     (binv3),
        
        .start_i     (dom_start_r),
        .done_o      (dom_done)
    );

endmodule

`default_nettype wire