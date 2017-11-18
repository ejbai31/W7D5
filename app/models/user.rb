class User < ApplicationRecord
  validates :username, :password_digest, :session_token, presence: true
  validate :password, length: { minimum: 6, allow_nil: true }

  attr_reader :password
  after_initialize :ensure_token

  def self.find_by_credentials(username, pw)
    user = User.find_by(username: username)
    return nil unless user && user.is_password(pw)
  end

  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end

  def reset_token
    self.session_token = SecureRandom.urlsafe_base64
    self.save
    self.session_token
  end

  def is_password?(pw)
    BCrypt::Password.new(password_digest).is_password?(pw)
  end

  private
  def ensure_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end
end
