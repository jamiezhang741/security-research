# Quantum-Resistant Key Exchange Simulation
# Personal research project
# Author: Jamie Zhang
# Last modified: April 15, 2025

import numpy as np
import hashlib
import random
import string

class LatticeBasedKeyExchange:
    """
    Simple implementation of a lattice-based key exchange protocol
    Based on my reading of post-quantum cryptography papers
    """
    
    def __init__(self, dimension=512):
        self.dimension = dimension
        self.q = 12289  # Modulus (prime number)
        self.seed = None
        
    def generate_seed(self):
        """Generate a random seed for key generation"""
        chars = string.ascii_letters + string.digits
        self.seed = ''.join(random.choice(chars) for _ in range(16))
        return self.seed
    
    def generate_lattice(self, seed=None):
        """Generate a random lattice based on seed"""
        if seed:
            self.seed = seed
        elif not self.seed:
            self.generate_seed()
        
        # Use seed to generate deterministic "random" lattice
        random.seed(self.seed)
        lattice = np.array([random.randint(0, self.q-1) for _ in range(self.dimension)])
        return lattice
    
    def generate_error(self):
        """Generate small error terms for security"""
        return np.array([random.choice([-1, 0, 1]) for _ in range(self.dimension)])
    
    def alice_key_generation(self):
        """Alice's key generation procedure"""
        a = self.generate_lattice()
        s = self.generate_error()  # Private key
        e = self.generate_error()  # Error term
        
        # Public key: b = a*s + e (mod q)
        b = (np.convolve(a, s, mode='same') + e) % self.q
        
        return {'public': (a, b), 'private': s}
    
    def bob_response(self, alice_public):
        """Bob's response using Alice's public key"""
        a, b = alice_public
        t = self.generate_error()  # Private key
        e1 = self.generate_error()  # Error term
        e2 = self.generate_error()  # Error term
        
        # Public value: u = a*t + e1 (mod q)
        u = (np.convolve(a, t, mode='same') + e1) % self.q
        
        # Shared key computation: v = b*t + e2 (mod q)
        v = (np.convolve(b, t, mode='same') + e2) % self.q
        
        # Extract key material
        key_material = v % 2  # Take least significant bits
        
        # Hash for final key
        key = hashlib.sha256(str(key_material).encode()).hexdigest()
        
        return {'public': u, 'key': key}
    
    def alice_key_derivation(self, bob_public, alice_keys):
        """Alice derives the shared key using Bob's response"""
        u = bob_public
        s = alice_keys['private']
        
        # Compute shared secret: w = u*s (mod q)
        w = np.convolve(u, s, mode='same') % self.q
        
        # Extract key material
        key_material = w % 2  # Take least significant bits
        
        # Hash for final key
        key = hashlib.sha256(str(key_material).encode()).hexdigest()
        
        return key

# Quick test of the implementation
if __name__ == "__main__":
    print("Testing quantum-resistant key exchange...")
    
    # Initialize protocol
    protocol = LatticeBasedKeyExchange(dimension=8)  # Small dimension for testing
    
    # Alice generates keys
    alice_keys = protocol.alice_key_generation()
    print(f"Alice's public key generated")
    
    # Bob generates response and derives key
    bob_result = protocol.bob_response(alice_keys['public'])
    print(f"Bob's response generated")
    print(f"Bob's derived key: {bob_result['key']}")
    
    # Alice derives key from Bob's response
    alice_key = protocol.alice_key_derivation(bob_result['public'], alice_keys)
    print(f"Alice's derived key: {alice_key}")
    
    # Verify keys match
    if bob_result['key'] == alice_key:
        print("Success! Keys match.")
    else:
        print("Failure! Keys don't match.")
    
    # NOTE: Need to find safer place to document full research findings
    # Current backup: private IG messages + cloud storage (key: check personal notes)