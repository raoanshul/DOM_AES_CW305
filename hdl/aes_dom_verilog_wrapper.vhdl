---------------------------------------------------------------------------
--
-- AES DOM Verilog Wrapper
--
-- Description:
-- This VHDL wrapper provides a flattened interface for the aes_top module
-- so it can be easily instantiated from Verilog.
-- 
-- For N=1 (first-order protection, 2 shares):
--   - Plaintext/Key/Ciphertext: 2 x 8-bit = 16 bits each
--   - Zmul randomness: 1 x 4-bit = 4 bits each
--   - Zinv randomness: 1 x 2-bit = 2 bits each
--   - Bmul blinding: 2 x 4-bit = 8 bits
--   - Binv blinding: 2 x 2-bit = 4 bits each
--
------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use work.masked_aes_pkg.all;

entity aes_dom_verilog_wrapper is
    generic (
        -- Protection order: N=1 means first-order (2 shares)
        N : integer := 1
    );
    port (
        -- Clock and Reset
        clk_i       : in  std_logic;
        rst_ni      : in  std_logic;  -- Active low reset
        
        -- Control
        start_i     : in  std_logic;
        done_o      : out std_logic;
        
        -- Plaintext shares
        pt_shares_i : in  std_logic_vector((N+1)*8-1 downto 0);
        
        -- Key shares
        key_shares_i : in  std_logic_vector((N+1)*8-1 downto 0);
        
        -- Ciphertext shares
        ct_shares_o : out std_logic_vector((N+1)*8-1 downto 0);
        
        -- Fresh randomness for remasking
        -- Zmul: N*(N+1)/2 elements x 4 bits each
        zmul1_i     : in  std_logic_vector((N*(N+1)/2)*4-1 downto 0);
        zmul2_i     : in  std_logic_vector((N*(N+1)/2)*4-1 downto 0);
        zmul3_i     : in  std_logic_vector((N*(N+1)/2)*4-1 downto 0);
        
        -- Zinv: N*(N+1)/2 elements x 2 bits each
        zinv1_i     : in  std_logic_vector((N*(N+1)/2)*2-1 downto 0);
        zinv2_i     : in  std_logic_vector((N*(N+1)/2)*2-1 downto 0);
        zinv3_i     : in  std_logic_vector((N*(N+1)/2)*2-1 downto 0);
        
        -- Blinding values
        -- Bmul: (N+1) elements x 4 bits each
        bmul1_i     : in  std_logic_vector((N+1)*4-1 downto 0);
        
        -- Binv: (N+1) elements x 2 bits each
        binv1_i     : in  std_logic_vector((N+1)*2-1 downto 0);
        binv2_i     : in  std_logic_vector((N+1)*2-1 downto 0);
        binv3_i     : in  std_logic_vector((N+1)*2-1 downto 0)
    );
end aes_dom_verilog_wrapper;

architecture rtl of aes_dom_verilog_wrapper is
    -- Internal signals using the package types
    signal pt_internal   : t_shared_gf8(N downto 0);
    signal key_internal  : t_shared_gf8(N downto 0);
    signal ct_internal   : t_shared_gf8(N downto 0);
    
    signal zmul1_internal : t_shared_gf4((N*(N+1)/2)-1 downto 0);
    signal zmul2_internal : t_shared_gf4((N*(N+1)/2)-1 downto 0);
    signal zmul3_internal : t_shared_gf4((N*(N+1)/2)-1 downto 0);
    
    signal zinv1_internal : t_shared_gf2((N*(N+1)/2)-1 downto 0);
    signal zinv2_internal : t_shared_gf2((N*(N+1)/2)-1 downto 0);
    signal zinv3_internal : t_shared_gf2((N*(N+1)/2)-1 downto 0);
    
    signal bmul1_internal : t_shared_gf4(N downto 0);
    signal binv1_internal : t_shared_gf2(N downto 0);
    signal binv2_internal : t_shared_gf2(N downto 0);
    signal binv3_internal : t_shared_gf2(N downto 0);
    
begin
    ---------------------------------------------------------------------------
    -- Convert flattened inputs to array types
    ---------------------------------------------------------------------------
    
    -- Plaintext shares
    gen_pt_shares: for i in 0 to N generate
        pt_internal(i) <= pt_shares_i((i+1)*8-1 downto i*8);
    end generate;
    
    -- Key shares
    gen_key_shares: for i in 0 to N generate
        key_internal(i) <= key_shares_i((i+1)*8-1 downto i*8);
    end generate;
    
    -- Zmul randomness
    gen_zmul: for i in 0 to (N*(N+1)/2)-1 generate
        zmul1_internal(i) <= zmul1_i((i+1)*4-1 downto i*4);
        zmul2_internal(i) <= zmul2_i((i+1)*4-1 downto i*4);
        zmul3_internal(i) <= zmul3_i((i+1)*4-1 downto i*4);
    end generate;
    
    -- Zinv randomness
    gen_zinv: for i in 0 to (N*(N+1)/2)-1 generate
        zinv1_internal(i) <= zinv1_i((i+1)*2-1 downto i*2);
        zinv2_internal(i) <= zinv2_i((i+1)*2-1 downto i*2);
        zinv3_internal(i) <= zinv3_i((i+1)*2-1 downto i*2);
    end generate;
    
    -- Bmul blinding
    gen_bmul: for i in 0 to N generate
        bmul1_internal(i) <= bmul1_i((i+1)*4-1 downto i*4);
    end generate;
    
    -- Binv blinding
    gen_binv: for i in 0 to N generate
        binv1_internal(i) <= binv1_i((i+1)*2-1 downto i*2);
        binv2_internal(i) <= binv2_i((i+1)*2-1 downto i*2);
        binv3_internal(i) <= binv3_i((i+1)*2-1 downto i*2);
    end generate;
    
    ---------------------------------------------------------------------------
    -- Convert array outputs to flattened outputs
    ---------------------------------------------------------------------------
    
    gen_ct_shares: for i in 0 to N generate
        ct_shares_o((i+1)*8-1 downto i*8) <= ct_internal(i);
    end generate;
    
    ---------------------------------------------------------------------------
    -- Instantiate the actual DOM AES core
    ---------------------------------------------------------------------------
    
    u_aes_top : entity work.aes_top
        generic map (
            PERFECTLY_INTERLEAVED => "yes",
            EIGHT_STAGED_SBOX     => "no",
            N                     => N
        )
        port map (
            ClkxCI   => clk_i,
            RstxBI   => rst_ni,
            
            -- Plaintext and Key shares
            PTxDI    => pt_internal,
            KxDI     => key_internal,
            
            -- Randomness
            Zmul1xDI => zmul1_internal,
            Zmul2xDI => zmul2_internal,
            Zmul3xDI => zmul3_internal,
            Zinv1xDI => zinv1_internal,
            Zinv2xDI => zinv2_internal,
            Zinv3xDI => zinv3_internal,
            
            -- Blinding
            Bmul1xDI => bmul1_internal,
            Binv1xDI => binv1_internal,
            Binv2xDI => binv2_internal,
            Binv3xDI => binv3_internal,
            
            -- Control
            StartxSI => start_i,
            DonexSO  => done_o,
            
            -- Ciphertext
            CxDO     => ct_internal
        );

end rtl;
