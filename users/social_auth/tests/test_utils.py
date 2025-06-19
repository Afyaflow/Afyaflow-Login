from django.test import TestCase
from ..utils import PKCEManager, StateManager

class PKCEManagerTests(TestCase):
    def test_generate_code_verifier(self):
        """Test that the code verifier is a high-entropy URL-safe string."""
        verifier1 = PKCEManager.generate_code_verifier()
        verifier2 = PKCEManager.generate_code_verifier()
        
        self.assertIsInstance(verifier1, str)
        self.assertGreaterEqual(len(verifier1), 43)
        self.assertLessEqual(len(verifier1), 128)
        self.assertNotEqual(verifier1, verifier2, "Verifiers should be random and not equal")
        # Check if it's URL-safe (no '+' or '/' characters)
        self.assertNotIn('+', verifier1)
        self.assertNotIn('/', verifier1)

    def test_generate_code_challenge(self):
        """Test that the code challenge is the Base64-URL-encoded SHA256 hash of the verifier."""
        verifier = "a" * 43
        challenge = PKCEManager.generate_code_challenge(verifier)
        
        # This is the known SHA256 hash of "a"*43, then Base64-URL encoded
        expected_challenge = 'ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA'
        self.assertEqual(challenge, expected_challenge)
        
        # Test with a different verifier
        verifier2 = "b" * 43
        challenge2 = PKCEManager.generate_code_challenge(verifier2)
        self.assertNotEqual(challenge, challenge2)


class StateManagerTests(TestCase):
    def test_generate_state(self):
        """Test that the state is a sufficiently random URL-safe string."""
        state1 = StateManager.generate_state()
        state2 = StateManager.generate_state()

        self.assertIsInstance(state1, str)
        self.assertGreaterEqual(len(state1), 32)
        self.assertNotEqual(state1, state2, "States should be random and not equal")
        
    def test_validate_state(self):
        """Test the secure comparison of state values."""
        session_state = StateManager.generate_state()
        
        # Test with matching states
        self.assertTrue(StateManager.validate_state(session_state, session_state))
        
        # Test with non-matching states
        different_state = StateManager.generate_state()
        self.assertFalse(StateManager.validate_state(session_state, different_state))
        
        # Test with empty or None values
        self.assertFalse(StateManager.validate_state(session_state, ""))
        self.assertFalse(StateManager.validate_state("", session_state))
        self.assertFalse(StateManager.validate_state(None, session_state))
        self.assertFalse(StateManager.validate_state(session_state, None))
        self.assertFalse(StateManager.validate_state(None, None)) 