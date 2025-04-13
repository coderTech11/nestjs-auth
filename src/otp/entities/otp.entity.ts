import { User } from 'src/user/entities/user.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { OTPType } from '../type/otpType';

@Entity()
export class OTP {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, { nullable: false })
  @JoinColumn()
  user: User;

  @Column()
  token: string; //hashed otp for verification

  @Column({ type: 'enum', enum: OTPType })
  type: OTPType;

  @Column()
  expiresAt: Date;

  @CreateDateColumn()
  createdAt: Date;
}
