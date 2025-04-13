import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { UserDto } from './dto/user.dto';
import * as bcrypt from 'bcryptjs';
import { OTPService } from 'src/otp/otp.service';
import { OTPType } from 'src/otp/type/otpType';
import { EmailService } from 'src/email/email.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly otpService: OTPService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
  ) {}

  //register user
  async register(dto: UserDto): Promise<void> {
    const { email, password } = dto;

    //check if email exist
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });

    if (existingUser) {
      throw new BadRequestException({ message: 'Email already exists' });
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
    });

    await this.userRepository.save(newUser);
    return this.emailVerification(newUser, OTPType.OTP);
  }

  //send otp or reset link via email
  async emailVerification(user: User, otpType: OTPType) {
    const token = await this.otpService.generateToken(user, otpType);

    if (otpType === OTPType.OTP) {
      const emailDto = {
        recipients: [user.email],
        subject: 'OTP for verification',
        html: `Your otp code is: <strong>${token}</strong>.
      <br />Provide this otp to verify your account`,
      };

      //send otp via email
      return await this.emailService.sendEmail(emailDto);
    } else if (otpType === OTPType.RESET_LINK) {
      const resetLink = `${this.configService.get('RESET_PASSWORD_URL')}?token=${token}`;
      const emailDto = {
        recipients: [user.email],
        subject: 'Password Reset Link',
        html: `Click the given link to reset your password: 
        <p><a href="${resetLink}">Reset Password</a></p>`,
      };

      //send reset link via email
      return await this.emailService.sendEmail(emailDto);
    }
  }

  //find by email
  async findByEmail(email: string): Promise<User> {
    return await this.userRepository.findOne({ where: { email } });
  }
}
