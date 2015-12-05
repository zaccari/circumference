module Circumference
  module Inspectable
    def inspect
      "#<#{self.class}:#{self.name}>"
    end
  end
end